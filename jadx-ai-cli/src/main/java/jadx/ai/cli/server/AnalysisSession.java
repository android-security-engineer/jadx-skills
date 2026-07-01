package jadx.ai.cli.server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.ai.cli.daemon.DaemonCache;

/**
 * An isolated analysis session for a single APK.
 * Each session holds its own JadxDecompiler and cache — no cross-session interference.
 */
public class AnalysisSession {

	private final String sessionId;
	private final String inputPath;
	private final JadxDecompiler decompiler;
	private final DaemonCache cache;
	private final long createdAt;
	private long lastAccessedAt;

	public AnalysisSession(String sessionId, String inputPath, JadxArgs jadxArgs) throws Exception {
		this.sessionId = sessionId;
		this.inputPath = inputPath;
		this.decompiler = new JadxDecompiler(jadxArgs);
		this.decompiler.load();
		this.cache = new DaemonCache(5 * 60_000, 500); // 5min TTL, 500 entries
		this.createdAt = System.currentTimeMillis();
		this.lastAccessedAt = this.createdAt;
	}

	public String getSessionId() {
		return sessionId;
	}

	public String getInputPath() {
		return inputPath;
	}

	public JadxDecompiler getDecompiler() {
		touch();
		return decompiler;
	}

	public DaemonCache getCache() {
		touch();
		return cache;
	}

	public long getCreatedAt() {
		return createdAt;
	}

	public long getLastAccessedAt() {
		return lastAccessedAt;
	}

	public int getClassCount() {
		return decompiler.getClasses().size();
	}

	public long getMemoryEstimateMB() {
		return (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024);
	}

	public void touch() {
		this.lastAccessedAt = System.currentTimeMillis();
	}

	public Map<String, Object> toStatusMap() {
		Map<String, Object> status = new HashMap<>();
		status.put("sessionId", sessionId);
		status.put("inputPath", inputPath);
		status.put("classCount", getClassCount());
		status.put("createdAt", createdAt);
		status.put("lastAccessedAt", lastAccessedAt);
		DaemonCache.CacheStats cacheStats = cache.getStats();
		status.put("cacheSize", cacheStats.size);
		status.put("cacheHitRate", String.format("%.2f%%", cacheStats.hitRate * 100));
		return status;
	}

	public void close() {
		try {
			decompiler.close();
		} catch (Exception ignored) {
		}
		cache.invalidateAll();
	}
}
