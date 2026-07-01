package jadx.ai.cli.server;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;

/**
 * Manages multiple APK analysis sessions within a single server.
 * Each session is identified by a unique sessionId and holds its own
 * JadxDecompiler + DaemonCache — no cross-session interference.
 *
 * Session ID resolution order:
 * 1. Explicit sessionId in request
 * 2. APK path in request → lookup by inputPath
 * 3. Default session (first loaded)
 */
public class SessionManager {

	private final ConcurrentHashMap<String, AnalysisSession> sessions = new ConcurrentHashMap<>();
	private volatile String defaultSessionId;

	/**
	 * Open a new analysis session for an APK file.
	 *
	 * @param inputPath path to the APK/DEX/JAR file
	 * @param jadxArgs  pre-configured JadxArgs (caller sets inputFile, options, etc.)
	 * @return the created session
	 */
	public AnalysisSession openSession(String inputPath, JadxArgs jadxArgs) throws Exception {
		String sessionId = generateSessionId(inputPath);
		if (sessions.containsKey(sessionId)) {
			throw new IllegalStateException("Session already exists for: " + inputPath
					+ " (sessionId=" + sessionId + ")");
		}

		AnalysisSession session = new AnalysisSession(sessionId, inputPath, jadxArgs);
		sessions.put(sessionId, session);

		// First session becomes default
		if (defaultSessionId == null) {
			defaultSessionId = sessionId;
		}

		return session;
	}

	/**
	 * Close and remove a session by ID.
	 */
	public boolean closeSession(String sessionId) {
		AnalysisSession session = sessions.remove(sessionId);
		if (session != null) {
			session.close();
			// If we removed the default, pick a new one
			if (sessionId.equals(defaultSessionId)) {
				defaultSessionId = sessions.isEmpty() ? null : sessions.keys().nextElement();
			}
			return true;
		}
		return false;
	}

	/**
	 * Resolve a session from request args.
	 * Looks for: sessionId → inputPath → default
	 */
	public AnalysisSession resolveSession(Map<String, Object> args) {
		// 1. Explicit session ID
		if (args != null && args.containsKey("sessionId")) {
			String sid = (String) args.get("sessionId");
			AnalysisSession session = sessions.get(sid);
			if (session != null) {
				return session;
			}
		}

		// 2. APK path lookup
		if (args != null && args.containsKey("inputPath")) {
			String inputPath = (String) args.get("inputPath");
			for (AnalysisSession s : sessions.values()) {
				if (s.getInputPath().equals(inputPath)) {
					return s;
				}
			}
		}

		// 3. Default session
		if (defaultSessionId != null) {
			return sessions.get(defaultSessionId);
		}

		return null;
	}

	/**
	 * Get session by exact ID.
	 */
	public AnalysisSession getSession(String sessionId) {
		return sessions.get(sessionId);
	}

	public String getDefaultSessionId() {
		return defaultSessionId;
	}

	public int getSessionCount() {
		return sessions.size();
	}

	public List<Map<String, Object>> listSessions() {
		List<Map<String, Object>> list = new ArrayList<>();
		for (AnalysisSession session : sessions.values()) {
			Map<String, Object> info = session.toStatusMap();
			info.put("isDefault", session.getSessionId().equals(defaultSessionId));
			list.add(info);
		}
		return list;
	}

	public void closeAll() {
		for (AnalysisSession session : sessions.values()) {
			try {
				session.close();
			} catch (Exception ignored) {
			}
		}
		sessions.clear();
		defaultSessionId = null;
	}

	private String generateSessionId(String inputPath) {
		// Generate a short, stable ID from the file name
		String name = new File(inputPath).getName();
		int dotIdx = name.lastIndexOf('.');
		if (dotIdx > 0) {
			name = name.substring(0, dotIdx);
		}
		// Add a hash suffix to avoid collisions if same-named files in different dirs
		int hash = inputPath.hashCode();
		return name + "-" + Integer.toHexString(Math.abs(hash)).substring(0, 4);
	}
}
