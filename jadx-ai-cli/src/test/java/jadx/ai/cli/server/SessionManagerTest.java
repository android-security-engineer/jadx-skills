package jadx.ai.cli.server;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SessionManager — the core of multi-APK support.
 */
class SessionManagerTest {

	private SessionManager manager;

	@BeforeEach
	void setUp() {
		manager = new SessionManager();
	}

	@AfterEach
	void tearDown() {
		manager.closeAll();
	}

	@Test
	void testEmptyManager() {
		assertEquals(0, manager.getSessionCount());
		assertNull(manager.getDefaultSessionId());
		assertNull(manager.getSession("nonexistent"));
	}

	@Test
	void testResolveSessionWithNoSessions() {
		Map<String, Object> args = new HashMap<>();
		assertNull(manager.resolveSession(args));
	}

	@Test
	void testResolveSessionWithNullArgs() {
		assertNull(manager.resolveSession(null));
	}

	@Test
	void testResolveSessionWithUnknownSessionId() {
		Map<String, Object> args = new HashMap<>();
		args.put("sessionId", "nonexistent");
		assertNull(manager.resolveSession(args));
	}

	@Test
	void testListSessionsEmpty() {
		List<Map<String, Object>> sessions = manager.listSessions();
		assertTrue(sessions.isEmpty());
	}

	@Test
	void testCloseNonexistentSession() {
		assertFalse(manager.closeSession("nonexistent"));
	}

	@Test
	void testCloseAllEmpty() {
		manager.closeAll();
		assertEquals(0, manager.getSessionCount());
	}

	@Test
	void testSessionIdGeneration() {
		// Session IDs should be deterministic for same input path
		String id1 = generateSessionId("/path/to/app.apk");
		String id2 = generateSessionId("/path/to/app.apk");
		assertEquals(id1, id2);

		// Different paths should generate different IDs
		String id3 = generateSessionId("/path/to/other.apk");
		assertNotEquals(id1, id3);
	}

	private String generateSessionId(String inputPath) {
		String name = new java.io.File(inputPath).getName();
		int dotIdx = name.lastIndexOf('.');
		if (dotIdx > 0) {
			name = name.substring(0, dotIdx);
		}
		int hash = inputPath.hashCode();
		return name + "-" + Integer.toHexString(Math.abs(hash)).substring(0, 4);
	}
}
