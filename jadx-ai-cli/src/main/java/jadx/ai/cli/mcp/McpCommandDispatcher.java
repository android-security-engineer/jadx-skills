package jadx.ai.cli.mcp;

import java.io.File;
import java.util.Map;

import jadx.ai.cli.commands.ClassDetailCommand;
import jadx.ai.cli.commands.CommentCommand;
import jadx.ai.cli.commands.DecompileCommand;
import jadx.ai.cli.commands.ExportCommand;
import jadx.ai.cli.commands.GraphCommand;
import jadx.ai.cli.commands.HookCommand;
import jadx.ai.cli.commands.InfoCommand;
import jadx.ai.cli.commands.LineMapCommand;
import jadx.ai.cli.commands.ListCommand;
import jadx.ai.cli.commands.NavigateCommand;
import jadx.ai.cli.commands.PackageDetailCommand;
import jadx.ai.cli.commands.RenameCommand;
import jadx.ai.cli.commands.ResourcesCommand;
import jadx.ai.cli.commands.SearchCommand;
import jadx.ai.cli.commands.UsageCommand;
import jadx.api.JadxDecompiler;

/**
 * Bridges MCP tool calls to existing Command classes.
 */
public class McpCommandDispatcher {

	private final JadxDecompiler decompiler;

	public McpCommandDispatcher(JadxDecompiler decompiler) {
		this.decompiler = decompiler;
	}

	public Object dispatch(String toolName, Map<String, Object> args) throws Exception {
		switch (toolName) {
			case "jadx_search":
				return dispatchSearch(args);
			case "jadx_decompile":
				return dispatchDecompile(args);
			case "jadx_class_detail":
				return dispatchClassDetail(args);
			case "jadx_usage":
				return dispatchUsage(args);
			case "jadx_list":
				return dispatchList(args);
			case "jadx_info":
				return dispatchInfo();
			case "jadx_rename":
				return dispatchRename(args);
			case "jadx_graph":
				return dispatchGraph(args);
			case "jadx_hook":
				return dispatchHook(args);
			case "jadx_navigate":
				return dispatchNavigate(args);
			case "jadx_comment":
				return dispatchComment(args);
			case "jadx_resources":
				return dispatchResources(args);
			case "jadx_line_map":
				return dispatchLineMap(args);
			case "jadx_export":
				return dispatchExport(args);
			case "jadx_package_detail":
				return dispatchPackageDetail(args);
			default:
				throw new IllegalArgumentException("Unknown tool: " + toolName);
		}
	}

	private Object dispatchSearch(Map<String, Object> args) throws Exception {
		SearchCommand cmd = new SearchCommand();
		cmd.searchType = (String) args.getOrDefault("type", "class");
		cmd.query = (String) args.getOrDefault("query", "");
		cmd.limit = args.containsKey("limit") ? ((Number) args.get("limit")).intValue() : 50;
		cmd.exact = Boolean.TRUE.equals(args.get("exact"));
		cmd.searchParent = Boolean.TRUE.equals(args.get("searchParent"));
		cmd.regex = Boolean.TRUE.equals(args.get("regex"));
		cmd.ignoreCase = Boolean.TRUE.equals(args.get("ignoreCase"));
		cmd.packageFilter = (String) args.get("package");
		cmd.resourceTypeFilter = (String) args.get("resourceType");
		cmd.maxResourceSizeKB = args.containsKey("maxSize") ? ((Number) args.get("maxSize")).intValue() : 512;
		return cmd.execute(decompiler);
	}

	private Object dispatchDecompile(Map<String, Object> args) throws Exception {
		DecompileCommand cmd = new DecompileCommand();
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.withSmali = Boolean.TRUE.equals(args.get("withSmali"));
		cmd.includeLineMap = Boolean.TRUE.equals(args.get("lineMap"));
		return cmd.execute(decompiler);
	}

	private Object dispatchClassDetail(Map<String, Object> args) throws Exception {
		ClassDetailCommand cmd = new ClassDetailCommand();
		cmd.className = (String) args.get("class");
		return cmd.execute(decompiler);
	}

	private Object dispatchUsage(Map<String, Object> args) throws Exception {
		UsageCommand cmd = new UsageCommand();
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.fieldName = (String) args.get("field");
		cmd.queryType = (String) args.getOrDefault("type", "useIn");
		cmd.depth = args.containsKey("depth") ? ((Number) args.get("depth")).intValue() : 1;
		return cmd.execute(decompiler);
	}

	private Object dispatchList(Map<String, Object> args) throws Exception {
		ListCommand cmd = new ListCommand();
		cmd.listType = (String) args.getOrDefault("type", "class");
		cmd.packageName = (String) args.get("package");
		cmd.withInners = Boolean.TRUE.equals(args.get("withInners"));
		cmd.limit = args.containsKey("limit") ? ((Number) args.get("limit")).intValue() : 100;
		return cmd.execute(decompiler);
	}

	private Object dispatchInfo() throws Exception {
		InfoCommand cmd = new InfoCommand();
		return cmd.execute(decompiler);
	}

	private Object dispatchRename(Map<String, Object> args) throws Exception {
		RenameCommand cmd = new RenameCommand();
		cmd.targetType = (String) args.getOrDefault("type", "class");
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.fieldName = (String) args.get("field");
		cmd.packageName = (String) args.get("package");
		cmd.newName = (String) args.get("name");
		cmd.removeAlias = Boolean.TRUE.equals(args.get("removeAlias"));
		return cmd.execute(decompiler);
	}

	private Object dispatchGraph(Map<String, Object> args) throws Exception {
		GraphCommand cmd = new GraphCommand();
		cmd.graphType = (String) args.getOrDefault("type", "call");
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.depth = args.containsKey("depth") ? ((Number) args.get("depth")).intValue() : 3;
		cmd.outputFormat = (String) args.getOrDefault("format", "json");
		return cmd.execute(decompiler);
	}

	private Object dispatchHook(Map<String, Object> args) throws Exception {
		HookCommand cmd = new HookCommand();
		cmd.hookType = (String) args.getOrDefault("type", "frida");
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.fieldName = (String) args.get("field");
		cmd.xposedLang = (String) args.getOrDefault("lang", "java");
		return cmd.execute(decompiler);
	}

	private Object dispatchNavigate(Map<String, Object> args) throws Exception {
		NavigateCommand cmd = new NavigateCommand();
		cmd.navType = (String) args.getOrDefault("type", "entry-points");
		return cmd.execute(decompiler);
	}

	private Object dispatchComment(Map<String, Object> args) throws Exception {
		CommentCommand cmd = new CommentCommand();
		cmd.className = (String) args.get("class");
		cmd.opType = (String) args.getOrDefault("type", "list");
		cmd.query = (String) args.get("query");
		return cmd.execute(decompiler);
	}

	private Object dispatchResources(Map<String, Object> args) throws Exception {
		ResourcesCommand cmd = new ResourcesCommand();
		cmd.resourceType = (String) args.get("type");
		cmd.nameFilter = (String) args.get("name");
		cmd.includeContent = Boolean.TRUE.equals(args.get("content"));
		return cmd.execute(decompiler);
	}

	private Object dispatchLineMap(Map<String, Object> args) throws Exception {
		LineMapCommand cmd = new LineMapCommand();
		cmd.className = (String) args.get("class");
		cmd.includeAnnotations = Boolean.TRUE.equals(args.get("annotations"));
		cmd.includeUsageMap = Boolean.TRUE.equals(args.get("usageMap"));
		cmd.usePlacesNode = (String) args.get("usePlaces");
		cmd.sourceLine = args.containsKey("sourceLine") ? ((Number) args.get("sourceLine")).intValue() : -1;
		cmd.nodeAtPos = args.containsKey("nodeAt") ? ((Number) args.get("nodeAt")).intValue() : -1;
		cmd.closestNodePos = args.containsKey("closestNode") ? ((Number) args.get("closestNode")).intValue() : -1;
		cmd.enclosingNodePos = args.containsKey("enclosingNode") ? ((Number) args.get("enclosingNode")).intValue() : -1;
		cmd.annotationAtPos = args.containsKey("annotationAt") ? ((Number) args.get("annotationAt")).intValue() : -1;
		return cmd.execute(decompiler);
	}

	private Object dispatchExport(Map<String, Object> args) throws Exception {
		ExportCommand cmd = new ExportCommand();
		String outputPath = (String) args.get("output");
		if (outputPath != null) {
			cmd.outputDir = new File(outputPath);
		}
		cmd.packageFilter = (String) args.get("package");
		cmd.classFilter = (String) args.get("class");
		cmd.exportFormat = (String) args.getOrDefault("format", "java");
		cmd.saveAll = Boolean.TRUE.equals(args.get("saveAll"));
		cmd.saveSources = Boolean.TRUE.equals(args.get("saveSources"));
		cmd.saveResources = Boolean.TRUE.equals(args.get("saveResources"));
		return cmd.execute(decompiler);
	}

	private Object dispatchPackageDetail(Map<String, Object> args) throws Exception {
		PackageDetailCommand cmd = new PackageDetailCommand();
		cmd.packageName = (String) args.get("package");
		return cmd.execute(decompiler);
	}
}
