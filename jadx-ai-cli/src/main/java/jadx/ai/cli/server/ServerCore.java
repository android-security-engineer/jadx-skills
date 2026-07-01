package jadx.ai.cli.server;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.ai.cli.daemon.DaemonCache;
import jadx.ai.cli.commands.ServerCommandDispatcher;

/**
 * Unified server core — the single source of truth for all command processing.
 * Supports multiple APK analysis sessions simultaneously.
 *
 * All transports (TCP, MCP, HTTP) delegate to this core.
 */
public class ServerCore {

	private final SessionManager sessionManager = new SessionManager();
	private final AtomicBoolean running = new AtomicBoolean(false);
	private final long startTime = System.currentTimeMillis();
	private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
	private ServerCommandDispatcher dispatcher;
	private Path pidFile;

	public void start() throws Exception {
		dispatcher = new ServerCommandDispatcher(sessionManager);
		running.set(true);
	}

	/**
	 * Load an APK into a new analysis session.
	 */
	public AnalysisSession loadApk(String inputPath, JadxArgs jadxArgs) throws Exception {
		return sessionManager.openSession(inputPath, jadxArgs);
	}

	/**
	 * Execute a command — ALL transports call this.
	 * Resolves the target session, then dispatches the command.
	 */
	public CommandResult executeCommand(String command, Map<String, Object> args) {
		long start = System.currentTimeMillis();

		// System commands don't need a session
		if (isSystemCommand(command)) {
			return executeSystemCommand(command, args, start);
		}

		// Resolve session for APK-specific commands
		AnalysisSession session = sessionManager.resolveSession(args);
		if (session == null) {
			return CommandResult.error("No active session. Load an APK first with 'session-open' or start server with an input file.", System.currentTimeMillis() - start);
		}

		// Check cache for read-only commands
		boolean isReadOnly = dispatcher.isReadOnlyCommand(command);
		String cacheKey = session.getSessionId() + ":" + command + ":" + gson.toJson(args);

		if (isReadOnly) {
			DaemonCache cache = session.getCache();
			Object cached = cache.get(cacheKey);
			if (cached != null) {
				return CommandResult.cached(cached, System.currentTimeMillis() - start);
			}
		}

		// Dispatch to command handler
		try {
			Object result = dispatcher.dispatch(command, args, session);

			// Cache read-only results
			if (isReadOnly) {
				session.getCache().put(cacheKey, result);
			}

			// Invalidate cache on mutations
			if (!isReadOnly) {
				session.getCache().invalidateAll();
			}

			return CommandResult.success(result, System.currentTimeMillis() - start);
		} catch (Exception e) {
			return CommandResult.error(e, System.currentTimeMillis() - start);
		}
	}

	/**
	 * System commands (don't need a session).
	 */
	private CommandResult executeSystemCommand(String command, Map<String, Object> args, long start) {
		try {
			switch (command) {
				case "ping":
					return CommandResult.success("pong", System.currentTimeMillis() - start);
				case "status":
					return CommandResult.success(buildStatus(), System.currentTimeMillis() - start);
				case "session-open":
					return handleSessionOpen(args, start);
				case "session-close":
					return handleSessionClose(args, start);
				case "session-list":
					return CommandResult.success(sessionManager.listSessions(), System.currentTimeMillis() - start);
				case "shutdown":
					return CommandResult.success("shutting down", System.currentTimeMillis() - start);
				case "cache-stats":
					return handleCacheStats(args, start);
				case "cache-clear":
					return handleCacheClear(args, start);
				default:
					return CommandResult.error("Unknown system command: " + command, System.currentTimeMillis() - start);
			}
		} catch (Exception e) {
			return CommandResult.error(e, System.currentTimeMillis() - start);
		}
	}

	private CommandResult handleSessionOpen(Map<String, Object> args, long start) throws Exception {
		String inputPath = (String) args.get("inputPath");
		if (inputPath == null) {
			return CommandResult.error("inputPath is required for session-open", System.currentTimeMillis() - start);
		}
		File inputFile = new File(inputPath);
		if (!inputFile.exists()) {
			return CommandResult.error("File not found: " + inputPath, System.currentTimeMillis() - start);
		}

		JadxArgs jadxArgs = new JadxArgs();
		jadxArgs.setInputFile(inputFile);
		jadxArgs.setSkipResources(false);

		// Apply optional deobfuscation
		if (Boolean.TRUE.equals(args.get("deobfuscation"))) {
			jadxArgs.setDeobfuscationOn(true);
		}

		AnalysisSession session = sessionManager.openSession(inputPath, jadxArgs);
		return CommandResult.success(session.toStatusMap(), System.currentTimeMillis() - start);
	}

	private CommandResult handleSessionClose(Map<String, Object> args, long start) {
		String sessionId = (String) args.get("sessionId");
		if (sessionId == null) {
			return CommandResult.error("sessionId is required for session-close", System.currentTimeMillis() - start);
		}
		boolean closed = sessionManager.closeSession(sessionId);
		Map<String, Object> result = new HashMap<>();
		result.put("sessionId", sessionId);
		result.put("closed", closed);
		return CommandResult.success(result, System.currentTimeMillis() - start);
	}

	private CommandResult handleCacheStats(Map<String, Object> args, long start) {
		AnalysisSession session = sessionManager.resolveSession(args);
		if (session == null) {
			return CommandResult.error("No active session", System.currentTimeMillis() - start);
		}
		DaemonCache.CacheStats stats = session.getCache().getStats();
		Map<String, Object> result = new HashMap<>();
		result.put("sessionId", session.getSessionId());
		result.put("size", stats.size);
		result.put("maxSize", stats.maxSize);
		result.put("ttlMs", stats.ttlMs);
		result.put("hits", stats.hits);
		result.put("misses", stats.misses);
		result.put("hitRate", String.format("%.2f%%", stats.hitRate * 100));
		return CommandResult.success(result, System.currentTimeMillis() - start);
	}

	private CommandResult handleCacheClear(Map<String, Object> args, long start) {
		AnalysisSession session = sessionManager.resolveSession(args);
		if (session == null) {
			return CommandResult.error("No active session", System.currentTimeMillis() - start);
		}
		session.getCache().invalidateAll();
		Map<String, Object> result = new HashMap<>();
		result.put("sessionId", session.getSessionId());
		result.put("status", "cleared");
		return CommandResult.success(result, System.currentTimeMillis() - start);
	}

	private boolean isSystemCommand(String command) {
		switch (command) {
			case "ping":
			case "status":
			case "session-open":
			case "session-close":
			case "session-list":
			case "shutdown":
			case "cache-stats":
			case "cache-clear":
				return true;
			default:
				return false;
		}
	}

	private Map<String, Object> buildStatus() {
		Map<String, Object> status = new HashMap<>();
		status.put("status", running.get() ? "running" : "stopped");
		status.put("uptimeMs", System.currentTimeMillis() - startTime);
		status.put("sessionCount", sessionManager.getSessionCount());
		status.put("sessions", sessionManager.listSessions());
		status.put("memoryUsedMB", (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024));
		return status;
	}

	public void writePidFile(int port) throws Exception {
		this.pidFile = Path.of(System.getProperty("java.io.tmpdir"), "jadx-ai-server-" + port + ".pid");
		String pid = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];
		Files.writeString(pidFile, pid + "\n" + port);
	}

	public void deletePidFile() {
		if (pidFile != null) {
			try {
				Files.deleteIfExists(pidFile);
			} catch (Exception ignored) {
			}
		}
	}

	public void stop() {
		running.set(false);
		sessionManager.closeAll();
		deletePidFile();
	}

	public boolean isRunning() {
		return running.get();
	}

	public SessionManager getSessionManager() {
		return sessionManager;
	}
}
