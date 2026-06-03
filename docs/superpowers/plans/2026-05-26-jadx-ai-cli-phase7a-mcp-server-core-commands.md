# JADX-AI-CLI Phase 7A: MCP Server + Core GUI Parity Commands

> Steps use checkbox (`- [ ]`) syntax.

**Goal:** Introduce MCP Server mode (stdio JSON-RPC) for persistent AI agent integration, and add the highest-priority missing GUI capabilities: comment CRUD, control flow graph generation, and APK signature/certificate display.

**Architecture:** AI agent sends JSON-RPC 2.0 over stdio → JadxMcpServer (long-lived JVM with loaded JadxDecompiler) → McpCommandDispatcher bridges to existing Command classes → returns structured JSON. JadxDecompiler persists across calls, eliminating 5-15s APK reload. Comment CRUD uses `JadxCodeData` + `ICodeComment` from jadx-core. CFG uses `DotGraphUtils.dumpToString()`. Signature uses `ApkVerifier`.

**Tech Stack:** Java 11+, Gson 2.10.1 (manual JSON-RPC over stdio), JadxDecompiler API, picocli 4.7.5, `com.android.tools.build:apksig:8.13.1`

**Scope:** Large | **Risk:** Medium | **Autonomy Level:** Full

**Risks:**
- Task 1 MCP server is new module — additive only, no existing behavior affected
- Task 2 Comment CRUD mutates `JadxCodeData` — must call `decompiler.reloadCodeData()` after each write
- Task 3 CFG needs `MethodNode` internals → accessible via `JavaMethod.getMethodNode()`
- Task 4 Signature adds `apksig` dependency — already proven in jadx-gui

---

### Task 1: Create MCP Server Module — stdio JSON-RPC for AI agent integration

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/JadxMcpServer.java`
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpToolDefinitions.java`
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpCommandDispatcher.java`
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/McpCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java` (add McpCommand import + subcommand)

- [ ] **Step 1: Create McpCommandDispatcher — bridges MCP tool calls to existing Command classes**

Create file `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpCommandDispatcher.java`. This class accepts a tool name and args map, instantiates the corresponding Command class, sets its fields, and calls `cmd.execute(decompiler)`. It dispatches all 15 tools: jadx_search, jadx_decompile, jadx_class_detail, jadx_usage, jadx_list, jadx_info, jadx_rename, jadx_graph, jadx_hook, jadx_navigate, jadx_comment, jadx_resources, jadx_line_map, jadx_export, jadx_package_detail. Pattern for each dispatch method: instantiate command → set fields from args map → call `cmd.execute(decompiler)`. The dispatch method for each command mirrors the pattern already used in `DaemonServer.java:201-316`.

- [ ] **Step 2: Create McpToolDefinitions — declares all 15 MCP tools with input schemas**

Create file `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpToolDefinitions.java`. This class has a static `getAll()` method returning `List<Map<String, Object>>` where each map has keys: `name`, `description`, `inputSchema`. The inputSchema follows JSON Schema format with `type: object`, `properties`, and `required` arrays. Each tool definition specifies its parameters with types and descriptions. Use helper methods `arg()` for required params and `optArg()` for optional params to keep definitions concise.

- [ ] **Step 3: Create JadxMcpServer — main MCP server entry point reading JSON-RPC from stdin**

Create file `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/JadxMcpServer.java`. This class:
1. Takes a `JadxDecompiler` instance (already loaded) in constructor
2. Creates a `McpCommandDispatcher` and `McpToolDefinitions`
3. Reads JSON-RPC requests from stdin line-by-line (one JSON object per line)
4. Dispatches based on `method` field: `initialize` → return capabilities; `tools/list` → return tool definitions; `tools/call` → extract tool name + args, call dispatcher; `ping` → return pong
5. Writes JSON-RPC responses to stdout
6. Uses Gson for JSON serialization/deserialization
7. Runs in a loop until stdin is closed
8. All responses follow JSON-RPC 2.0 format: `{"jsonrpc":"2.0","id":<id>,"result":<data>}` or `{"jsonrpc":"2.0","id":<id>,"error":{"code":-32600,"message":"..."}}`

- [ ] **Step 4: Create McpCommand — picocli subcommand that starts the MCP server**

Create file `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/McpCommand.java`:

```java
package jadx.ai.cli.commands;

import java.io.File;

import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import jadx.ai.cli.mcp.JadxMcpServer;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;

@Command(name = "mcp", description = "Start MCP server (JSON-RPC over stdio) for AI agent integration")
public class McpCommand implements Runnable {

	@Parameters(index = "0", description = "Input file (APK, DEX, JAR, AAR)")
	protected File inputFile;

	@Override
	public void run() {
		try {
			JadxArgs args = new JadxArgs();
			args.setInputFile(inputFile);
			args.setSkipResources(false);
			JadxDecompiler decompiler = new JadxDecompiler(args);
			decompiler.load();
			JadxMcpServer server = new JadxMcpServer(decompiler);
			server.run();
		} catch (Exception e) {
			System.err.println("MCP server error: " + e.getMessage());
		}
	}
}
```

- [ ] **Step 5: Register McpCommand in JadxAICLI — add subcommand entry**

Modify `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`:
- Add import: `import jadx.ai.cli.commands.McpCommand;`
- Add `McpCommand.class` to the `subcommands` array in the `@Command` annotation (after `CommentCommand.class`)

- [ ] **Step 6: Verify MCP server starts correctly**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"
  - Output does NOT contain: "error" or "cannot find symbol"

- [ ] **Step 7: Commit**

Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/ jadx-ai-cli/src/main/java/jadx/ai/cli/commands/McpCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(jadx-ai-cli): add MCP server module with stdio JSON-RPC transport"`

---

### Task 2: Enhance CommentCommand — add full CRUD for code comments

**Depends on:** None
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/CommentCommand.java` (rewrite with add/update/delete operations)
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java:195-198` (make jadxArgs accessible for codeData)

- [ ] **Step 1: Modify AbstractCommand — expose JadxArgs for code data access**

Modify `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java`. Extract the JadxArgs construction logic from `run()` into a protected method `buildJadxArgs()` so that subclasses (like CommentCommand) can access the args object to set/get `codeData`. Specifically, add a protected field `protected JadxArgs jadxArgs;` and assign it before `new JadxDecompiler(args)`. Change the local variable `args` to use `this.jadxArgs` so subclasses can access it after execution.

- [ ] **Step 2: Rewrite CommentCommand with full CRUD — add/update/delete/search comments**

Rewrite `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/CommentCommand.java` with operations:
- `list` (existing): list all comments for a class
- `search` (existing): search comments by keyword
- `add`: add a comment using `JadxCodeComment(nodeRef, codeRef, comment, style)`. Required params: `--class`, `--comment-text`. Optional: `--method`, `--field`, `--style` (LINE/BLOCK/JAVADOC etc, default LINE), `--insn-offset` (for instruction-level comments)
- `update`: update existing comment at (nodeRef, codeRef) location. Required: `--class`, `--comment-text`. Finds existing by (nodeRef, codeRef), removes old, adds new
- `delete`: delete comment at (nodeRef, codeRef) location. Required: `--class`. Optional: `--method`, `--field`, `--insn-offset`
- After each write operation (add/update/delete): get `JadxCodeData` from `jadxArgs.getCodeData()`, mutate the comments list, call `Collections.sort(list)`, set back, then call `decompiler.reloadCodeData()` to apply changes

The comment creation uses jadx-core API:
```java
JadxNodeRef nodeRef = className != null ? JadxNodeRef.forCls(className) : ...;
JadxCodeRef codeRef = insnOffset >= 0 ? JadxCodeRef.forInsn(insnOffset) : null;
ICodeComment comment = new JadxCodeComment(nodeRef, codeRef, text, CommentStyle.LINE);
```

- [ ] **Step 3: Verify comment commands compile**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: Commit**

Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/CommentCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/commands/AbstractCommand.java && git commit -m "feat(jadx-ai-cli): add comment CRUD (add/update/delete) to CommentCommand"`

---

### Task 3: Create CfgCommand — control flow graph generation

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/CfgCommand.java`
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java` (add CfgCommand subcommand)

- [ ] **Step 1: Create CfgCommand — generate CFG in dot/mermaid/text format**

Create file `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/CfgCommand.java`:

```java
package jadx.ai.cli.commands;

import java.util.HashMap;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.core.utils.DotGraphUtils;

@Command(name = "cfg", description = "Generate control flow graph for a method")
public class CfgCommand extends AbstractCommand {

	@Option(names = {"-c", "--class"}, description = "Class name", required = true)
	protected String className;

	@Option(names = {"-m", "--method"}, description = "Method name (required for CFG)")
	protected String methodName;

	@Option(names = {"--cfg-type"}, description = "CFG type: basic, raw, region", defaultValue = "basic")
	protected String cfgType;

	@Option(names = {"--format"}, description = "Output format: dot, text", defaultValue = "dot")
	protected String outputFormat;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}
		if (methodName == null) {
			return JsonOutput.error("MethodRequired", "Method name is required for CFG generation");
		}
		JavaMethod method = null;
		for (JavaMethod m : cls.getMethods()) {
			if (m.getName().equals(methodName)) {
				method = m;
				break;
			}
		}
		if (method == null) {
			return JsonOutput.error("MethodNotFound", "Method not found: " + methodName);
		}

		boolean useRegions = "region".equals(cfgType);
		boolean rawInsn = "raw".equals(cfgType);
		DotGraphUtils utils = new DotGraphUtils(useRegions, rawInsn);
		String dotGraph = utils.dumpToString(method.getMethodNode());
		if (dotGraph == null) {
			return JsonOutput.error("NoGraph", "Could not generate CFG (method may have no basic blocks)");
		}

		Map<String, Object> result = new HashMap<>();
		result.put("class", cls.getFullName());
		result.put("method", method.getName());
		result.put("cfgType", cfgType);
		result.put("format", outputFormat);
		result.put("graph", dotGraph);
		return JsonOutput.ok(result);
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("class", className);
		args.put("method", methodName);
		args.put("cfgType", cfgType);
		args.put("format", outputFormat);
		return args;
	}
}
```

- [ ] **Step 2: Register CfgCommand in JadxAICLI**

Modify `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`:
- Add import: `import jadx.ai.cli.commands.CfgCommand;`
- Add `CfgCommand.class` to the `subcommands` array

- [ ] **Step 3: Verify CfgCommand compiles**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: Commit**

Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/commands/CfgCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(jadx-ai-cli): add CfgCommand for control flow graph generation"`

---

### Task 4: Create SignatureCommand — APK signature verification and certificate display

**Depends on:** None
**Files:**
- Create: `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SignatureCommand.java`
- Modify: `jadx-ai-cli/build.gradle.kts:17-26` (add apksig dependency)
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java` (add SignatureCommand subcommand)

- [ ] **Step 1: Add apksig dependency to build.gradle.kts**

Modify `jadx-ai-cli/build.gradle.kts`, add after the existing `implementation("info.picocli:picocli:4.7.5")` line:

```kotlin
implementation("com.android.tools.build:apksig:8.13.1")
```

- [ ] **Step 2: Create SignatureCommand — verify APK signatures and display certificates**

Create file `jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SignatureCommand.java`:

```java
package jadx.ai.cli.commands;

import java.io.File;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import com.android.apksig.ApkVerifier;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;

@Command(name = "signature", description = "Verify APK signature and display certificate details")
public class SignatureCommand extends AbstractCommand {

	@Option(names = {"--no-verify"}, description = "Skip verification, only show certificates")
	protected boolean skipVerify;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		File apkFile = decompiler.getArgs().getInputFiles().isEmpty()
				? inputFile
				: decompiler.getArgs().getInputFiles().get(0);
		if (apkFile == null || !apkFile.exists()) {
			return JsonOutput.error("NoInput", "APK file not found");
		}

		Map<String, Object> result = new HashMap<>();
		result.put("file", apkFile.getName());

		if (!skipVerify) {
			ApkVerifier verifier = new ApkVerifier.Builder(apkFile).build();
			ApkVerifier.Result verifyResult = verifier.verify();

			result.put("verified", verifyResult.isVerified());
			result.put("v1Scheme", verifyResult.isVerifiedUsingV1Scheme());
			result.put("v2Scheme", verifyResult.isVerifiedUsingV2Scheme());
			result.put("v3Scheme", verifyResult.isVerifiedUsingV3Scheme());
			result.put("v31Scheme", verifyResult.isVerifiedUsingV31Scheme());

			List<Map<String, Object>> errors = new ArrayList<>();
			for (ApkVerifier.IssueWithParams err : verifyResult.getErrors()) {
				Map<String, Object> e = new HashMap<>();
				e.put("issue", err.getIssue().name());
				e.put("message", err.toString());
				errors.add(e);
			}
			result.put("errors", errors);

			List<Map<String, Object>> warnings = new ArrayList<>();
			for (ApkVerifier.IssueWithParams warn : verifyResult.getWarnings()) {
				Map<String, Object> w = new HashMap<>();
				w.put("issue", warn.getIssue().name());
				w.put("message", warn.toString());
				warnings.add(w);
			}
			result.put("warnings", warnings);

			List<Map<String, Object>> signers = new ArrayList<>();
			collectSigners(verifyResult.getV1SchemeSigners(), "V1", signers);
			collectSigners(verifyResult.getV2SchemeSigners(), "V2", signers);
			collectSigners(verifyResult.getV3SchemeSigners(), "V3", signers);
			collectSigners(verifyResult.getV31SchemeSigners(), "V3.1", signers);
			result.put("signers", signers);
		}

		return JsonOutput.ok(result);
	}

	private void collectSigners(List<? extends ApkVerifier.SignerInfo> signerInfos, String scheme, List<Map<String, Object>> signers) {
		for (ApkVerifier.SignerInfo info : signerInfos) {
			Map<String, Object> signer = new HashMap<>();
			signer.put("scheme", scheme);
			if (info.getName() != null) {
				signer.put("name", info.getName());
			}
			if (info.getIndex() >= 0) {
				signer.put("index", info.getIndex());
			}
			if (info.getCertificate() instanceof X509Certificate) {
				signer.put("certificate", extractCertInfo((X509Certificate) info.getCertificate()));
			}
			List<String> signerErrors = new ArrayList<>();
			for (ApkVerifier.IssueWithParams err : info.getErrors()) {
				signerErrors.add(err.getIssue().name() + ": " + err.toString());
			}
			if (!signerErrors.isEmpty()) {
				signer.put("errors", signerErrors);
			}
			signers.add(signer);
		}
	}

	private Map<String, Object> extractCertInfo(X509Certificate cert) {
		Map<String, Object> info = new HashMap<>();
		info.put("subject", cert.getSubjectDN().toString());
		info.put("issuer", cert.getIssuerDN().toString());
		info.put("serialNumber", cert.getSerialNumber().toString(16));
		info.put("validFrom", cert.getNotBefore().toString());
		info.put("validUntil", cert.getNotAfter().toString());
		info.put("signatureAlgorithm", cert.getSigAlgName());
		try {
			info.put("fingerprintMD5", getThumbprint(cert, "MD5"));
			info.put("fingerprintSHA1", getThumbprint(cert, "SHA-1"));
			info.put("fingerprintSHA256", getThumbprint(cert, "SHA-256"));
		} catch (Exception ignored) {
		}
		return info;
	}

	private static String getThumbprint(X509Certificate cert, String algorithm) throws Exception {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		byte[] digest = md.digest(cert.getEncoded());
		StringBuilder sb = new StringBuilder();
		for (byte b : digest) {
			sb.append(String.format("%02X", b));
			sb.append(":");
		}
		if (sb.length() > 0) {
			sb.setLength(sb.length() - 1);
		}
		return sb.toString();
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("skipVerify", skipVerify);
		return args;
	}
}
```

- [ ] **Step 3: Register SignatureCommand in JadxAICLI**

Modify `jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java`:
- Add import: `import jadx.ai.cli.commands.SignatureCommand;`
- Add `SignatureCommand.class` to the `subcommands` array

- [ ] **Step 4: Verify SignatureCommand compiles**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 5: Commit**

Run: `git add jadx-ai-cli/build.gradle.kts jadx-ai-cli/src/main/java/jadx/ai/cli/commands/SignatureCommand.java jadx-ai-cli/src/main/java/jadx/ai/cli/JadxAICLI.java && git commit -m "feat(jadx-ai-cli): add SignatureCommand for APK signature verification and certificate display"`

---

### Task 5: Register new commands in Daemon + MCP dispatcher

**Depends on:** Task 1, Task 2, Task 3, Task 4
**Files:**
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java:182-199` (add new daemon commands)
- Modify: `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpCommandDispatcher.java` (add cfg, signature tools)

- [ ] **Step 1: Register cfg, signature commands in DaemonServer**

Modify `jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java` method `buildRegistry()` (line ~182). Add after `reg.register("cache-clear", ...)`:

```java
reg.register("cfg", args -> executeCfg(args));
reg.register("signature", args -> executeSignature());
```

Add corresponding execution methods:

```java
private Object executeCfg(Map<String, Object> args) throws Exception {
	CfgCommand cmd = new CfgCommand();
	cmd.className = (String) args.get("class");
	cmd.methodName = (String) args.get("method");
	cmd.cfgType = (String) args.getOrDefault("cfgType", "basic");
	cmd.outputFormat = (String) args.getOrDefault("format", "dot");
	return cmd.execute(decompiler);
}

private Object executeSignature() throws Exception {
	SignatureCommand cmd = new SignatureCommand();
	return cmd.execute(decompiler);
}
```

- [ ] **Step 2: Add jadx_cfg and jadx_signature tools to MCP dispatcher**

Modify `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpCommandDispatcher.java` — add two new cases in the `dispatch` switch:

```java
case "jadx_cfg":
	return dispatchCfg(args);
case "jadx_signature":
	return dispatchSignature();
```

Add dispatch methods:

```java
private Object dispatchCfg(Map<String, Object> args) throws Exception {
	CfgCommand cmd = new CfgCommand();
	cmd.className = (String) args.get("class");
	cmd.methodName = (String) args.get("method");
	cmd.cfgType = (String) args.getOrDefault("cfgType", "basic");
	cmd.outputFormat = (String) args.getOrDefault("format", "dot");
	return cmd.execute(decompiler);
}

private Object dispatchSignature() throws Exception {
	SignatureCommand cmd = new SignatureCommand();
	return cmd.execute(decompiler);
}
```

Also modify `jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpToolDefinitions.java` — add two new tool definitions:

```java
tools.add(tool("jadx_cfg", "Generate control flow graph for a method",
		arg("class", "string", "Full class name", null),
		arg("method", "string", "Method name", null),
		optArg("cfgType", "string", "CFG type: basic, raw, region", "basic"),
		optArg("format", "string", "Output format: dot, text", "dot")));
tools.add(tool("jadx_signature", "Verify APK signature and display certificates",
		optArg("skipVerify", "boolean", "Skip verification", false)));
```

- [ ] **Step 3: Verify all registrations compile**

Run: `cd /data/local/tmp/workspace/github/AI-jadx && ./gradlew :jadx-ai-cli:compileJava 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "BUILD SUCCESSFUL"

- [ ] **Step 4: Commit**

Run: `git add jadx-ai-cli/src/main/java/jadx/ai/cli/daemon/DaemonServer.java jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpCommandDispatcher.java jadx-ai-cli/src/main/java/jadx/ai/cli/mcp/McpToolDefinitions.java && git commit -m "feat(jadx-ai-cli): register cfg and signature commands in daemon and MCP dispatcher"`
