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
import jadx.ai.cli.commands.CommandDispatch;

public class DaemonServer {

	/** Daemon-local control commands not backed by a {@link CommandDispatch} command. */
	private static final String CMD_CACHE_STATS = "cache-stats";
	private static final String CMD_CACHE_CLEAR = "cache-clear";

	private final JadxArgs jadxArgs;
	private final int port;
	private JadxDecompiler decompiler;
	private ServerSocket serverSocket;
	private final AtomicBoolean running = new AtomicBoolean(false);
	private final long startTime = System.currentTimeMillis();
	private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	private final Path pidFile;
	private DaemonCache cache;

	public DaemonServer(JadxArgs jadxArgs, int port) {
		this.jadxArgs = jadxArgs;
		this.port = port;
		this.pidFile = Path.of(System.getProperty("java.io.tmpdir"), "jadx-ai-daemon-" + port + ".pid");
	}

	public void start() throws Exception {
		decompiler = new JadxDecompiler(jadxArgs);
		decompiler.load();
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
				case CMD_CACHE_STATS:
					response.success = true;
					response.data = executeCacheStats();
					break;
				case CMD_CACHE_CLEAR:
					response.success = true;
					response.data = executeCacheClear();
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
			if (!CommandDispatch.isKnown(request.command)) {
				response.success = false;
				response.error = "Unknown command: " + request.command;
				return response;
			}
			boolean isReadOnly = CommandDispatch.isReadOnly(request.command);
			// Mutations invalidate the read-through cache before running.
			if (!isReadOnly && cache != null) {
				cache.invalidateAll();
			}
			String cacheKey = request.command + ":" + gson.toJson(args);
			if (isReadOnly && cache != null) {
				Object cached = cache.get(cacheKey);
				if (cached != null) {
					response.success = true;
					response.data = cached;
					return response;
				}
			}
			Object result = CommandDispatch.run(request.command, args, decompiler);
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
