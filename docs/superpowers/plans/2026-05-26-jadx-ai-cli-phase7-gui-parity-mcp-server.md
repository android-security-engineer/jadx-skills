# JADX-AI-CLI Phase 7: GUI Capability Parity + MCP Server Mode

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** Achieve full jadx-gui capability parity in jadx-ai-cli, and introduce an MCP Server mode so AI agents (Claude, Cursor, etc.) can continuously invoke jadx commands without JVM restart overhead.

**Architecture:** AI agent sends JSON-RPC over stdio → MCP Server (long-lived JVM process with loaded JadxDecompiler) → dispatches to existing Command classes → returns structured results. The JadxDecompiler instance persists across calls, eliminating 5-15s APK reload per invocation. Existing CLI and TCP daemon modes remain backward-compatible.

**Tech Stack:** Java 17+, MCP Java SDK 1.0.0 (`io.modelcontextprotocol.sdk:mcp`), Jackson 3.x, JadxDecompiler API, Gson, picocli

**Scope:** Large
**Risk:** Medium
**Risks:**
- Task 1 adds MCP SDK dependency — may conflict with existing Jackson version used by jadx-core → mitigated: MCP SDK bundles its own Jackson, jadx-core uses Gson
- Task 5 modifies shared DaemonServer for new command registrations → mitigated: additive changes only, no existing behavior altered
- JadxDecompiler is not designed for concurrent reads → mitigated: MCP server uses synchronized dispatch, same as current daemon
- MCP SDK requires Java 17+ → mitigated: jadx already targets Java 11; add conditional module that only loads when Java 17+ detected

**Autonomy Level:** Full

---

### Task 1: Create MCP Server Module — stdio transport for AI agent integration

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/JadxMcpServer.java`
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpToolDefinitions.java`
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpCommandDispatcher.java`
- Modify: `jadx-ai-cli/build.gradle` (add MCP SDK dependency)

- [ ] **Step 1: Add MCP SDK dependency to build.gradle**

```groovy
// In jadx-ai-cli/build.gradle, add to dependencies block:
implementation "io.modelcontextprotocol.sdk:mcp:1.0.0"
```

If the MCP SDK cannot be resolved from Maven Central, fall back to implementing the JSON-RPC protocol directly over stdin/stdout using only Gson (no external dependency). The protocol is simple: read newline-delimited JSON-RPC from stdin, write newline-delimited JSON-RPC to stdout.

- [ ] **Step 2: Create McpCommandDispatcher — bridges MCP tool calls to existing Command classes**

```java
package jadx.ai.cli.mcp;

import java.util.HashMap;
import java.util.Map;

import jadx.api.JadxDecompiler;
import jadx.ai.cli.commands.*;

public class McpCommandDispatcher {
	private final JadxDecompiler decompiler;

	public McpCommandDispatcher(JadxDecompiler decompiler) {
		this.decompiler = decompiler;
	}

	public Object dispatch(String toolName, Map<String, Object> args) throws Exception {
		switch (toolName) {
			case "jadx_search":
				return executeSearch(args);
			case "jadx_decompile":
				return executeDecompile(args);
			case "jadx_class_detail":
				return executeClassDetail(args);
			case "jadx_usage":
				return executeUsage(args);
			case "jadx_list":
				return executeList(args);
			case "jadx_info":
				return executeInfo();
			case "jadx_rename":
				return executeRename(args);
			case "jadx_reload":
				return executeReload(args);
			case "jadx_export":
				return executeExport(args);
			case "jadx_resources":
				return executeResources(args);
			case "jadx_line_map":
				return executeLineMap(args);
			case "jadx_package_detail":
				return executePackageDetail(args);
			case "jadx_graph":
				return executeGraph(args);
			case "jadx_hook":
				return executeHook(args);
			case "jadx_navigate":
				return executeNavigate(args);
			case "jadx_comment":
				return executeComment(args);
			default:
				throw new IllegalArgumentException("Unknown tool: " + toolName);
		}
	}

	private Object executeSearch(Map<String, Object> args) throws Exception {
		SearchCommand cmd = new SearchCommand();
		cmd.searchType = (String) args.getOrDefault("type", "class");
		cmd.query = (String) args.getOrDefault("query", "");
		cmd.limit = args.containsKey("limit") ? ((Number) args.get("limit")).intValue() : 50;
		cmd.exact = Boolean.TRUE.equals(args.get("exact"));
		cmd.ignoreCase = Boolean.TRUE.equals(args.get("ignoreCase"));
		cmd.packageFilter = (String) args.get("package");
		return cmd.execute(decompiler);
	}

	private Object executeDecompile(Map<String, Object> args) throws Exception {
		DecompileCommand cmd = new DecompileCommand();
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.showSmali = Boolean.TRUE.equals(args.get("smali"));
		return cmd.execute(decompiler);
	}

	private Object executeClassDetail(Map<String, Object> args) throws Exception {
		ClassDetailCommand cmd = new ClassDetailCommand();
		cmd.className = (String) args.get("class");
		return cmd.execute(decompiler);
	}

	private Object executeUsage(Map<String, Object> args) throws Exception {
		UsageCommand cmd = new UsageCommand();
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.usageType = (String) args.getOrDefault("type", "useIn");
		cmd.depth = args.containsKey("depth") ? ((Number) args.get("depth")).intValue() : 1;
		return cmd.execute(decompiler);
	}

	private Object executeList(Map<String, Object> args) throws Exception {
		ListCommand cmd = new ListCommand();
		cmd.listType = (String) args.getOrDefault("type", "class");
		cmd.packageFilter = (String) args.get("package");
		cmd.limit = args.containsKey("limit") ? ((Number) args.get("limit")).intValue() : 100;
		return cmd.execute(decompiler);
	}

	private Object executeInfo() throws Exception {
		InfoCommand cmd = new InfoCommand();
		return cmd.execute(decompiler);
	}

	private Object executeRename(Map<String, Object> args) throws Exception {
		RenameCommand cmd = new RenameCommand();
		cmd.renameType = (String) args.get("type");
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.fieldName = (String) args.get("field");
		cmd.packageName = (String) args.get("package");
		cmd.newName = (String) args.get("name");
		return cmd.execute(decompiler);
	}

	private Object executeReload(Map<String, Object> args) throws Exception {
		ReloadCommand cmd = new ReloadCommand();
		cmd.className = (String) args.get("class");
		return cmd.execute(decompiler);
	}

	private Object executeExport(Map<String, Object> args) throws Exception {
		ExportCommand cmd = new ExportCommand();
		cmd.packageFilter = (String) args.get("package");
		cmd.outputFormat = (String) args.getOrDefault("format", "java");
		return cmd.execute(decompiler);
	}

	private Object executeResources(Map<String, Object> args) throws Exception {
		ResourcesCommand cmd = new ResourcesCommand();
		cmd.nameFilter = (String) args.get("name");
		cmd.resourceTypeFilter = (String) args.get("type");
		return cmd.execute(decompiler);
	}

	private Object executeLineMap(Map<String, Object> args) throws Exception {
		LineMapCommand cmd = new LineMapCommand();
		cmd.className = (String) args.get("class");
		cmd.mapType = (String) args.getOrDefault("type", "annotations");
		return cmd.execute(decompiler);
	}

	private Object executePackageDetail(Map<String, Object> args) throws Exception {
		PackageDetailCommand cmd = new PackageDetailCommand();
		cmd.packageName = (String) args.get("package");
		return cmd.execute(decompiler);
	}

	private Object executeGraph(Map<String, Object> args) throws Exception {
		GraphCommand cmd = new GraphCommand();
		cmd.className = (String) args.get("class");
		cmd.graphType = (String) args.getOrDefault("type", "call");
		cmd.methodName = (String) args.get("method");
		cmd.depth = args.containsKey("depth") ? ((Number) args.get("depth")).intValue() : 2;
		cmd.outputFormat = (String) args.getOrDefault("format", "json");
		return cmd.execute(decompiler);
	}

	private Object executeHook(Map<String, Object> args) throws Exception {
		HookCommand cmd = new HookCommand();
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.fieldName = (String) args.get("field");
		cmd.hookType = (String) args.getOrDefault("type", "frida");
		cmd.xposedLang = (String) args.getOrDefault("lang", "java");
		return cmd.execute(decompiler);
	}

	private Object executeNavigate(Map<String, Object> args) throws Exception {
		NavigateCommand cmd = new NavigateCommand();
		cmd.navType = (String) args.getOrDefault("type", "entry-points");
		return cmd.execute(decompiler);
	}

	private Object executeComment(Map<String, Object> args) throws Exception {
		CommentCommand cmd = new CommentCommand();
		cmd.className = (String) args.get("class");
		cmd.opType = (String) args.getOrDefault("type", "list");
		cmd.query = (String) args.get("query");
		return cmd.execute(decompiler);
	}
}
```

- [ ] **Step 3: Create McpToolDefinitions — declares all MCP tools with JSON Schema**

```java
package jadx.ai.cli.mcp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class McpToolDefinitions {

	public static List<Map<String, Object>> getTools() {
		List<Map<String, Object>> tools = new ArrayList<>();
		tools.add(tool("jadx_search", "Search for classes, methods, fields, strings, or resources in the APK",
				prop("type", "string", "Search type: class, method, field, string, resource", "class"),
				prop("query", "string", "Search query string", null),
				optProp("limit", "integer", "Max results", 50),
				optProp("exact", "boolean", "Exact match only", false),
				optProp("package", "string", "Package filter", null)));
		tools.add(tool("jadx_decompile", "Decompile a class or method to Java source code",
				prop("class", "string", "Full class name", null),
				optProp("method", "string", "Method name (decompiles single method)", null),
				optProp("smali", "boolean", "Return smali instead of Java", false)));
		tools.add(tool("jadx_class_detail", "Get detailed info about a class: fields, methods, inheritance, interfaces",
				prop("class", "string", "Full class name", null)));
		tools.add(tool("jadx_usage", "Find where a class/method is used (useIn) or what it uses (usedBy)",
				prop("class", "string", "Full class name", null),
				optProp("method", "string", "Method name", null),
				optProp("type", "string", "Usage type: useIn, usedBy", "useIn"),
				optProp("depth", "integer", "Recursion depth", 1)));
		tools.add(tool("jadx_list", "List classes, packages, methods, or fields",
				optProp("type", "string", "List type: class, package, method, field", "class"),
				optProp("package", "string", "Package filter", null),
				optProp("limit", "integer", "Max results", 100)));
		tools.add(tool("jadx_info", "Get APK overview: package name, permissions, activities, class count"));
		tools.add(tool("jadx_rename", "Rename a class, method, field, or package",
				prop("type", "string", "Rename type: class, method, field, package", null),
				prop("name", "string", "New name", null),
				optProp("class", "string", "Class name (for method/field rename)", null),
				optProp("method", "string", "Method name", null),
				optProp("field", "string", "Field name", null),
				optProp("package", "string", "Package name", null)));
		tools.add(tool("jadx_graph", "Generate call graph, inheritance graph, or usage graph",
				prop("class", "string", "Full class name", null),
				optProp("type", "string", "Graph type: call, inheritance, usage", "call"),
				optProp("method", "string", "Method name for call graph", null),
				optProp("depth", "integer", "Graph depth", 2),
				optProp("format", "string", "Output format: json, mermaid, dot", "json")));
		tools.add(tool("jadx_hook", "Generate Frida or Xposed hook snippets",
				prop("class", "string", "Full class name", null),
				optProp("type", "string", "Hook type: frida, xposed", "frida"),
				optProp("method", "string", "Method name", null),
				optProp("field", "string", "Field name", null),
				optProp("lang", "string", "Xposed language: java, kotlin", "java")));
		tools.add(tool("jadx_navigate", "Discover APK entry points, main activity, application class",
				optProp("type", "string", "Navigation type: entry-points, main-activity, application, manifest", "entry-points")));
		tools.add(tool("jadx_comment", "Read code annotations and metadata for a class",
				prop("class", "string", "Full class name", null),
				optProp("type", "string", "Operation: list, search", "list"),
				optProp("query", "string", "Search keyword", null)));
		tools.add(tool("jadx_resources", "List APK resources (XML, images, etc.)",
				optProp("name", "string", "Resource name filter", null),
				optProp("type", "string", "Resource type filter", null)));
		tools.add(tool("jadx_line_map", "Get code annotations and node positions for a class",
				prop("class", "string", "Full class name", null),
				optProp("type", "string", "Map type: annotations, usage-map, node-at", "annotations")));
		tools.add(tool("jadx_export", "Export decompiled sources or specific packages",
				optProp("package", "string", "Package filter", null),
				optProp("format", "string", "Export format: java, smali, gradle", "java")));
		tools.add(tool("jadx_package_detail", "Get detailed info about a package",
				prop("package", "string", "Package name", null)));
		return tools;
	}

	private static Map<String, Object> tool(String name, String desc, Map<String, Object>... props) {
		Map<String, Object> t = new HashMap<>();
		t.put("name", name);
		t.put("description", desc);
		Map<String, Object> schema = new HashMap<>();
		schema.put("type", "object");
		Map<String, Object> properties = new HashMap<>();
		List<String> required = new ArrayList<>();
		for (Map<String, Object> p : props) {
			String pName = (String) p.get("name");
			p.remove("name");
			properties.put(pName, p);
			if (p.containsKey("_required")) {
				p.remove("_required");
				required.add(pName);
			}
		}
		schema.put("properties", properties);
		if (!required.isEmpty()) {
			schema.put("required", required);
		}
		t.put("inputSchema", schema);
		return t;
	}

	private static Map<String, Object> prop(String name, String type, String desc, Object def) {
		Map<String, Object> p = new HashMap<>();
		p.put("name", name);
		p.put("type", type);
		p.put("description", desc);
		if (def != null) {
			p.put("default", def);
		}
		p.put("_required", true);
		return p;
	}

	private static Map<String, Object> optProp(String name, String type, String desc, Object def) {
		Map<String, Object> p = new HashMap<>();
		p.put("name", name);
		p.put("type", type);
		p.put("description", desc);
		if (def != null) {
			p.put("default", def);
		}
		return p;
	}
}
```

- [ ] **Step 4: Create JadxMcpServer — the main MCP server entry point**

```java
package jadx.ai.cli.mcp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.ai.cli.commands.InfoCommand;

public class JadxMcpServer {

	private static final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	private static JadxDecompiler decompiler;
	private static McpCommandDispatcher dispatcher;

	public static void start(JadxArgs jadxArgs) throws Exception {
		decompiler = new JadxDecompiler(jadxArgs);
		decompiler.load();
		dispatcher = new McpCommandDispatcher(decompiler);

		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		System.err.println("[jadx-mcp] Server starting, " + decompiler.getClasses().size() + " classes loaded");

		String line;
		while ((line = reader.readLine()) != null) {
			try {
				Map<String, Object> request = gson.fromJson(line, Map.class);
				Map<String, Object> response = handleRequest(request);
				System.out.println(gson.toJson(response));
				System.out.flush();
			} catch (Exception e) {
				System.err.println("[jadx-mcp] Error: " + e.getMessage());
				Map<String, Object> errorResp = new HashMap<>();
				errorResp.put("jsonrpc", "2.0");
				errorResp.put("error", Map.of("code", -32603, "message", e.getMessage()));
				System.out.println(gson.toJson(errorResp));
				System.out.flush();
			}
		}

		decompiler.close();
		System.err.println("[jadx-mcp] Server shutting down");
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> handleRequest(Map<String, Object> request) throws Exception {
		String method = (String) request.get("method");
		Object id = request.get("id");
		Map<String, Object> params = (Map<String, Object>) request.getOrDefault("params", new HashMap<>());

		Map<String, Object> response = new HashMap<>();
		response.put("jsonrpc", "2.0");
		if (id != null) {
			response.put("id", id);
		}

		switch (method) {
			case "initialize":
				response.put("result", Map.of(
					"protocolVersion", "2025-11-25",
					"capabilities", Map.of("tools", Map.of("listChanged", true)),
					"serverInfo", Map.of("name", "jadx-mcp-server", "version", "1.0.0"),
					"instructions", "JADX decompiler MCP server. Use jadx_search to find classes, jadx_decompile to read source, jadx_usage to trace references, jadx_graph for call/inheritance graphs, jadx_hook for Frida/Xposed snippets."
				));
				break;
			case "notifications/initialized":
				return null; // No response for notifications
			case "ping":
				response.put("result", Map.of());
				break;
			case "tools/list":
				response.put("result", Map.of("tools", McpToolDefinitions.getTools()));
				break;
			case "tools/call":
				String toolName = (String) params.get("name");
				Map<String, Object> arguments = (Map<String, Object>) params.getOrDefault("arguments", new HashMap<>());
				Object result = dispatcher.dispatch(toolName, arguments);
				response.put("result", Map.of(
					"content", List.of(Map.of("type", "text", "text", gson.toJson(result))),
					"isError", false
				));
				break;
			default:
				response.put("error", Map.of("code", -32601, "message", "Method not found: " + method));
		}
		return response;
	}
}
```

- [ ] **Step 5: Register MCP server as CLI subcommand**

```java
// Add to jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java
// New import:
import jadx.ai.cli.commands.McpCommand;

// Add to subcommands array:
McpCommand.class
```

Create the McpCommand class:

```java
package jadx.ai.cli.commands;

import picocli.CommandLine.Command;
import jadx.ai.cli.mcp.JadxMcpServer;

@Command(name = "mcp", description = "Start MCP server for AI agent integration (stdio transport)")
public class McpCommand extends AbstractCommand {

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		// MCP server manages its own decompiler lifecycle
		JadxMcpServer.start(jadxArgs);
		return null;
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		return new java.util.HashMap<>();
	}
}
```

Note: `McpCommand` needs access to `jadxArgs` which is currently private in `AbstractCommand`. Change `jadxArgs` field visibility from private to protected in `AbstractCommand.java`.

- [ ] **Step 6: Verify MCP server starts**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}' | java -cp jadx-ai-cli/build/libs/jadx-ai-cli.jar jadx.ai.cli.JadxAICLI mcp --input test.apk 2>/dev/null | head -1`
Expected:
  - Output contains `"protocolVersion"` and `"jadx-mcp-server"`
  - No Java exception in stderr

---

### Task 2: Create MappingsCommand — ProGuard/Enigma/Tiny mapping import/export

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/MappingsCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java` (register subcommand)
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java` (register daemon command)

- [ ] **Step 1: Create MappingsCommand with import/export/list subcommands**

```java
package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

@Command(name = "mappings", description = "Import/export rename mappings (ProGuard, Enigma, Tiny)")
public class MappingsCommand extends AbstractCommand {

	@Option(names = {"-a", "--action"}, description = "Action: import, export, list", required = true)
	protected String action;

	@Option(names = {"-f", "--format"}, description = "Mapping format: proguard, enigma, tiny, tiny2", defaultValue = "proguard")
	protected String format;

	@Option(names = {"-p", "--path"}, description = "Path to mapping file (for import/export)")
	protected String mappingPath;

	@Option(names = {"--invert"}, description = "Invert mapping on import")
	protected boolean invert;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		switch (action) {
			case "import":
				return importMappings(decompiler);
			case "export":
				return exportMappings(decompiler);
			case "list":
				return listMappings(decompiler);
			default:
				return JsonOutput.error("InvalidAction", "Unknown action: " + action + ". Use: import, export, list");
		}
	}

	private Object importMappings(JadxDecompiler decompiler) throws Exception {
		if (mappingPath == null) {
			return JsonOutput.error("MissingPath", "--path is required for import");
		}
		java.io.File mappingFile = new java.io.File(mappingPath);
		if (!mappingFile.exists()) {
			return JsonOutput.error("FileNotFound", "Mapping file not found: " + mappingPath);
		}

		// Apply mappings by setting JadxArgs.userRenamesMappingsPath
		// This requires decompiler re-initialization (like GUI's MainWindow.reopen())
		java.nio.file.Path mappingsPath = mappingFile