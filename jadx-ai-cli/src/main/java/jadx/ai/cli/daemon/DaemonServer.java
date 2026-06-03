package jadx.ai.cli.daemon;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.api.ResourceFile;
import jadx.ai.cli.commands.CfgCommand;
import jadx.ai.cli.commands.ClassDetailCommand;
import jadx.ai.cli.commands.DecompileCommand;
import jadx.ai.cli.commands.ExportCommand;
import jadx.ai.cli.commands.InfoCommand;
import jadx.ai.cli.commands.LineMapCommand;
import jadx.ai.cli.commands.ListCommand;
import jadx.ai.cli.commands.PackageDetailCommand;
import jadx.ai.cli.commands.ReloadCommand;
import jadx.ai.cli.commands.RenameCommand;
import jadx.ai.cli.commands.ResourcesCommand;
import jadx.ai.cli.commands.SearchCommand;
import jadx.ai.cli.commands.SignatureCommand;
import jadx.ai.cli.commands.UsageCommand;

public class DaemonServer {

	private final JadxArgs jadxArgs;
	private final int port;
	private JadxDecompiler decompiler;
	private ServerSocket serverSocket;
	private final AtomicBoolean running = new AtomicBoolean(false);
	private final long startTime = System.currentTimeMillis();
	private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	private final Path pidFile;
	private DaemonCommandRegistry registry;
	private DaemonCache cache;

	public DaemonServer(JadxArgs jadxArgs, int port) {
		this.jadxArgs = jadxArgs;
		this.port = port;
		this.pidFile = Path.of(System.getProperty("java.io.tmpdir"), "jadx-ai-daemon-" + port + ".pid");
	}

	public void start() throws Exception {
		decompiler = new JadxDecompiler(jadxArgs);
		decompiler.load();
		registry = buildRegistry();
		cache = new DaemonCache(5 * 60 * 1000, 500);  // 5min TTL, 500 entries
		running.set(true);
		writePidFile();
		Runtime.getRuntime().addShutdownHook(new Thread(this::stop));
		serverSocket = new ServerSocket(port);
		System.out.println("JADX AI Daemon started on port " + port
				+ " with " + decompiler.getClasses().size() + " classes loaded");
		while (running.get()) {
			try {
				Socket client = serverSocket.accept();
				handleClient(client);
			} catch (java.net.SocketException e) {
				if (running.get()) {
					throw e;
				}
				break;
			}
		}
	}

	private void handleClient(Socket client) {
		try (BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
				OutputStream out = client.getOutputStream()) {
			String line = in.readLine();
			if (line == null) {
				return;
			}
			DaemonProtocol.Request request = gson.fromJson(line, DaemonProtocol.Request.class);
			if (!DaemonProtocol.MAGIC.equals(request.magic)) {
				sendError(out, "Invalid magic header");
				return;
			}
			DaemonProtocol.Response response = dispatch(request);
			String json = gson.toJson(response);
			out.write((json + "\n").getBytes("UTF-8"));
			out.flush();
		} catch (Exception e) {
			System.err.println("Error handling client: " + e.getMessage());
		} finally {
			try {
				client.close();
			} catch (IOException ignored) {
			}
		}
	}

	private DaemonProtocol.Response dispatch(DaemonProtocol.Request request) {
		long start = System.currentTimeMillis();
		DaemonProtocol.Response response = new DaemonProtocol.Response();
		try {
			switch (request.command) {
				case "ping":
					response.success = true;
					response.data = "pong";
					break;
				case "reload":
			case "rename":
				if (cache != null) {
					cache.invalidateAll();
				}
				break;
			case "shutdown":
					response.success = true;
					response.data = "shutting down";
					new Thread(() -> {
						try {
							Thread.sleep(100);
							stop();
						} catch (Exception ignored) {
						}
					}).start();
					break;
				case "status":
					response.success = true;
					response.data = buildStatus();
					break;
				default:
					response = executeCommand(request);
					break;
			}
		} catch (Exception e) {
			response.success = false;
			response.error = e.getMessage();
		}
		response.latencyMs = System.currentTimeMillis() - start;
		return response;
	}

	private DaemonProtocol.Response executeCommand(DaemonProtocol.Request request) {
		DaemonProtocol.Response response = new DaemonProtocol.Response();
		try {
			Map<String, Object> args = request.args != null ? request.args : new HashMap<>();
			if (!registry.hasCommand(request.command)) {
				response.success = false;
				response.error = "Unknown command: " + request.command;
				return response;
			}
			// Check cache for read-only commands
			boolean isReadOnly = isReadOnlyCommand(request.command);
			String cacheKey = request.command + ":" + gson.toJson(args);
			if (isReadOnly && cache != null) {
				Object cached = cache.get(cacheKey);
				if (cached != null) {
					response.success = true;
					response.data = cached;
					return response;
				}
			}
			Object result = registry.execute(request.command, args);
			if (isReadOnly && cache != null) {
				cache.put(cacheKey, result);
			}
			response.success = true;
			response.data = result;
		} catch (Exception e) {
			response.success = false;
			response.error = e.getClass().getSimpleName() + ": " + e.getMessage();
		}
		return response;
	}

	private DaemonCommandRegistry buildRegistry() {
		DaemonCommandRegistry reg = new DaemonCommandRegistry();
		reg.register("search", args -> executeSearch(args));
		reg.register("usage", args -> executeUsage(args));
		reg.register("list", args -> executeList(args));
		reg.register("info", args -> executeInfo());
		reg.register("class-detail", args -> executeClassDetail(args));
		reg.register("decompile", args -> executeDecompile(args));
		reg.register("rename", args -> executeRename(args));
		reg.register("reload", args -> executeReload(args));
		reg.register("export", args -> executeExport(args));
		reg.register("resources", args -> executeResources(args));
		reg.register("line-map", args -> executeLineMap(args));
		reg.register("package-detail", args -> executePackageDetail(args));
		reg.register("cache-stats", args -> executeCacheStats());
		reg.register("cache-clear", args -> executeCacheClear());
		reg.register("cfg", args -> executeCfg(args));
		reg.register("signature", args -> executeSignature());
		return reg;
	}

	private Object executeSearch(Map<String, Object> args) throws Exception {
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

	private Object executeUsage(Map<String, Object> args) throws Exception {
		UsageCommand cmd = new UsageCommand();
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.fieldName = (String) args.get("field");
		cmd.queryType = (String) args.getOrDefault("type", "useIn");
		cmd.depth = args.containsKey("depth") ? ((Number) args.get("depth")).intValue() : 1;
		return cmd.execute(decompiler);
	}

	private Object executeList(Map<String, Object> args) throws Exception {
		ListCommand cmd = new ListCommand();
		cmd.listType = (String) args.getOrDefault("type", "class");
		cmd.packageName = (String) args.get("package");
		cmd.withInners = Boolean.TRUE.equals(args.get("withInners"));
		cmd.limit = args.containsKey("limit") ? ((Number) args.get("limit")).intValue() : 100;
		return cmd.execute(decompiler);
	}

	private Object executeInfo() throws Exception {
		InfoCommand cmd = new InfoCommand();
		return cmd.execute(decompiler);
	}

	private Object executeClassDetail(Map<String, Object> args) throws Exception {
		ClassDetailCommand cmd = new ClassDetailCommand();
		cmd.className = (String) args.get("class");
		return cmd.execute(decompiler);
	}

	private Object executeDecompile(Map<String, Object> args) throws Exception {
		DecompileCommand cmd = new DecompileCommand();
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.withSmali = Boolean.TRUE.equals(args.get("withSmali"));
		cmd.includeLineMap = Boolean.TRUE.equals(args.get("lineMap"));
		return cmd.execute(decompiler);
	}

	private Object executeRename(Map<String, Object> args) throws Exception {
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

	private Object executeReload(Map<String, Object> args) throws Exception {
		ReloadCommand cmd = new ReloadCommand();
		cmd.className = (String) args.get("class");
		cmd.actionType = (String) args.getOrDefault("type", "reload");
		cmd.allClasses = Boolean.TRUE.equals(args.get("all"));
		return cmd.execute(decompiler);
	}

	private Object executeExport(Map<String, Object> args) throws Exception {
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

	private Object executeResources(Map<String, Object> args) throws Exception {
		ResourcesCommand cmd = new ResourcesCommand();
		cmd.resourceType = (String) args.get("type");
		cmd.nameFilter = (String) args.get("name");
		cmd.includeContent = Boolean.TRUE.equals(args.get("content"));
		return cmd.execute(decompiler);
	}

	private Object executeLineMap(Map<String, Object> args) throws Exception {
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

	private Object executePackageDetail(Map<String, Object> args) throws Exception {
		PackageDetailCommand cmd = new PackageDetailCommand();
		cmd.packageName = (String) args.get("package");
		return cmd.execute(decompiler);
	}

	private DaemonProtocol.StatusResponse buildStatus() {
		DaemonProtocol.StatusResponse status = new DaemonProtocol.StatusResponse();
		status.status = "running";
		status.inputFile = jadxArgs.getInputFiles().isEmpty() ? ""
				: jadxArgs.getInputFiles().get(0).getAbsolutePath();
		status.classCount = decompiler.getClasses().size();
		status.methodCount = decompiler.getClasses().stream()
				.mapToInt(c -> c.getMethods().size()).sum();
		status.uptimeMs = System.currentTimeMillis() - startTime;
		status.memoryUsedMB = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory())
				/ (1024 * 1024);
		return status;
	}

	private void sendError(OutputStream out, String message) throws IOException {
		DaemonProtocol.Response resp = new DaemonProtocol.Response();
		resp.success = false;
		resp.error = message;
		out.write((gson.toJson(resp) + "\n").getBytes("UTF-8"));
		out.flush();
	}

	private void writePidFile() throws IOException {
		String pid = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
		Files.writeString(pidFile, pid + "\n" + port);
	}

	public void stop() {
		running.set(false);
		try {
			if (serverSocket != null && !serverSocket.isClosed()) {
				serverSocket.close();
			}
		} catch (IOException ignored) {
		}
		try {
			if (decompiler != null) {
				decompiler.close();
			}
		} catch (Exception ignored) {
		}
		try {
			Files.deleteIfExists(pidFile);
		} catch (IOException ignored) {
		}
	}

	private boolean isReadOnlyCommand(String command) {
		switch (command) {
			case "reload":
			case "rename":
			case "export":
			case "cache-clear":
			case "shutdown":
			case "comment":
				return false;
			default:
				return true;
		}
	}

	private Object executeCacheStats() {
		if (cache == null) {
			return Map.of("enabled", false);
		}
		DaemonCache.CacheStats stats = cache.getStats();
		Map<String, Object> result = new HashMap<>();
		result.put("enabled", true);
		result.put("size", stats.size);
		result.put("maxSize", stats.maxSize);
		result.put("ttlMs", stats.ttlMs);
		result.put("hits", stats.hits);
		result.put("misses", stats.misses);
		result.put("hitRate", String.format("%.2f%%", stats.hitRate * 100));
		return result;
	}

	private Object executeCacheClear() {
		if (cache != null) {
			cache.invalidateAll();
		}
		return Map.of("status", "cleared");
	}

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

	public static void main(String[] args) throws Exception {
		String portStr = System.getProperty("jadx.daemon.port", String.valueOf(DaemonProtocol.DEFAULT_PORT));
		String inputPath = System.getProperty("jadx.daemon.input");
		if (inputPath == null && args.length > 0) {
			inputPath = args[0];
		}
		if (inputPath == null) {
			System.err.println("Usage: java -Djadx.daemon.input=<apk> -Djadx.daemon.port=<port> jadx.ai.cli.daemon.DaemonServer");
			System.exit(1);
		}
		JadxArgs jadxArgs = new JadxArgs();
		jadxArgs.setInputFiles(java.util.Collections.singletonList(new File(inputPath)));
		jadxArgs.setSkipResources(false);
		int port = Integer.parseInt(portStr);
		DaemonServer server = new DaemonServer(jadxArgs, port);
		server.start();
	}
}
