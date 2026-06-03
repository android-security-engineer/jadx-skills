package jadx.ai.cli.mcp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Defines all MCP tool specifications with JSON Schema input schemas.
 */
public class McpToolDefinitions {

	public static List<Map<String, Object>> getAll() {
		List<Map<String, Object>> tools = new ArrayList<>();
		tools.add(tool("jadx_search",
				"Search for classes, methods, fields, strings, or resources in the decompiled APK",
				arg("query", "string", "Search query string", ""),
				optArg("type", "string", "Search type: class, method, field, string, resource", "class"),
				optArg("limit", "integer", "Maximum number of results", 50),
				optArg("exact", "boolean", "Match exactly (no substring)", false),
				optArg("regex", "boolean", "Treat query as regex pattern", false),
				optArg("ignoreCase", "boolean", "Case-insensitive search", false),
				optArg("package", "string", "Filter results by package name", null),
				optArg("resourceType", "string", "Filter resources by type", null),
				optArg("maxSize", "integer", "Max resource size in KB", 512)));

		tools.add(tool("jadx_decompile",
				"Decompile a class or method to Java source code",
				arg("class", "string", "Full class name to decompile", null),
				optArg("method", "string", "Method name to decompile (optional, decompiles entire class if omitted)", null),
				optArg("withSmali", "boolean", "Include smali/disassembly output", false),
				optArg("lineMap", "boolean", "Include source-to-bytecode line mapping", false)));

		tools.add(tool("jadx_class_detail",
				"Get detailed information about a class including fields, methods, and hierarchy",
				arg("class", "string", "Full class name", null)));

		tools.add(tool("jadx_usage",
				"Find where a class, method, or field is used in the codebase",
				arg("class", "string", "Full class name", null),
				optArg("method", "string", "Method name to search usage for", null),
				optArg("field", "string", "Field name to search usage for", null),
				optArg("type", "string", "Usage type: useIn, usedBy", "useIn"),
				optArg("depth", "integer", "Traversal depth for usage chain", 1)));

		tools.add(tool("jadx_list",
				"List classes, packages, or methods in the APK",
				optArg("type", "string", "List type: class, package, method", "class"),
				optArg("package", "string", "Filter by package name", null),
				optArg("withInners", "boolean", "Include inner classes", false),
				optArg("limit", "integer", "Maximum number of results", 100)));

		tools.add(tool("jadx_info",
				"Get APK/DEX file information including package name, permissions, and class count"));

		tools.add(tool("jadx_rename",
				"Rename a class, method, field, or package in the decompiled output",
				arg("name", "string", "New name to apply", null),
				optArg("type", "string", "Rename target type: class, method, field, package", "class"),
				optArg("class", "string", "Class name (required for class/method/field rename)", null),
				optArg("method", "string", "Method name (for method rename)", null),
				optArg("field", "string", "Field name (for field rename)", null),
				optArg("package", "string", "Package name (for package rename)", null),
				optArg("removeAlias", "boolean", "Remove existing alias instead of setting new one", false)));

		tools.add(tool("jadx_graph",
				"Generate call graph, inheritance graph, or usage graph",
				optArg("type", "string", "Graph type: call, inheritance, usage", "call"),
				optArg("class", "string", "Target class name (required for call and usage graphs)", null),
				optArg("method", "string", "Target method name (optional, for call graph)", null),
				optArg("depth", "integer", "Max traversal depth", 3),
				optArg("format", "string", "Output format: json, mermaid, dot", "json")));

		tools.add(tool("jadx_hook",
				"Generate Frida or Xposed hook snippets for reverse engineering",
				arg("class", "string", "Target class name (full name)", null),
				optArg("type", "string", "Hook type: frida, xposed", "frida"),
				optArg("method", "string", "Target method name (optional, hooks all methods if not specified)", null),
				optArg("field", "string", "Target field name (optional)", null),
				optArg("lang", "string", "Xposed language: java, kotlin (only for xposed type)", "java")));

		tools.add(tool("jadx_navigate",
				"Navigate to APK entry points and key components (main activity, application class, manifest, etc.)",
				optArg("type", "string", "Navigation type: main-activity, application, manifest, entry-points", "entry-points")));

		tools.add(tool("jadx_comment",
				"Read code annotations and metadata comments from decompiled classes",
				arg("class", "string", "Target class name (full name)", null),
				optArg("type", "string", "Operation: list (all annotations), search (by keyword)", "list"),
				optArg("query", "string", "Search keyword for annotations (required for search type)", null)));

		tools.add(tool("jadx_resources",
				"List and read resources from the APK (manifest, layouts, strings, etc.)",
				optArg("type", "string", "Resource type filter (e.g., xml, png, json)", null),
				optArg("name", "string", "Resource name filter", null),
				optArg("content", "boolean", "Include resource content in output", false)));

		tools.add(tool("jadx_line_map",
				"Map between source line numbers and bytecode positions for a decompiled class",
				arg("class", "string", "Full class name", null),
				optArg("annotations", "boolean", "Include annotation positions", false),
				optArg("usageMap", "boolean", "Include usage mapping", false),
				optArg("usePlaces", "string", "Node name for use-places lookup", null),
				optArg("sourceLine", "integer", "Source line number to look up", -1),
				optArg("nodeAt", "integer", "Position to find node at", -1),
				optArg("closestNode", "integer", "Position to find closest node", -1),
				optArg("enclosingNode", "integer", "Position to find enclosing node", -1),
				optArg("annotationAt", "integer", "Position to find annotation at", -1)));

		tools.add(tool("jadx_export",
				"Export decompiled sources or resources to disk",
				optArg("output", "string", "Output directory path", null),
				optArg("package", "string", "Filter by package name", null),
				optArg("class", "string", "Filter by class name", null),
				optArg("format", "string", "Export format: java, gradle", "java"),
				optArg("saveAll", "boolean", "Save all (sources + resources)", false),
				optArg("saveSources", "boolean", "Save decompiled sources", false),
				optArg("saveResources", "boolean", "Save resources", false)));

		tools.add(tool("jadx_package_detail",
				"Get detailed information about a package including its classes",
				arg("package", "string", "Package name", null)));

		return tools;
	}

	private static Map<String, Object> arg(String name, String type, String desc, Object defaultValue) {
		Map<String, Object> param = new LinkedHashMap<>();
		param.put("name", name);
		param.put("type", type);
		param.put("description", desc);
		if (defaultValue != null) {
			param.put("default", defaultValue);
		}
		param.put("required", true);
		return param;
	}

	private static Map<String, Object> optArg(String name, String type, String desc, Object defaultValue) {
		Map<String, Object> param = new LinkedHashMap<>();
		param.put("name", name);
		param.put("type", type);
		param.put("description", desc);
		if (defaultValue != null) {
			param.put("default", defaultValue);
		}
		param.put("required", false);
		return param;
	}

	@SafeVarargs
	private static Map<String, Object> tool(String name, String desc, Map<String, Object>... params) {
		Map<String, Object> toolDef = new LinkedHashMap<>();
		toolDef.put("name", name);
		toolDef.put("description", desc);

		Map<String, Object> properties = new LinkedHashMap<>();
		List<String> required = new ArrayList<>();

		for (Map<String, Object> param : params) {
			String paramName = (String) param.get("name");
			String paramType = (String) param.get("type");
			String paramDesc = (String) param.get("description");
			boolean isRequired = Boolean.TRUE.equals(param.get("required"));

			Map<String, Object> propDef = new LinkedHashMap<>();
			propDef.put("type", paramType);
			propDef.put("description", paramDesc);
			if (param.containsKey("default")) {
				propDef.put("default", param.get("default"));
			}
			properties.put(paramName, propDef);

			if (isRequired) {
				required.add(paramName);
			}
		}

		Map<String, Object> inputSchema = new LinkedHashMap<>();
		inputSchema.put("type", "object");
		inputSchema.put("properties", properties);
		if (!required.isEmpty()) {
			inputSchema.put("required", required);
		}

		toolDef.put("inputSchema", inputSchema);
		return toolDef;
	}
}
