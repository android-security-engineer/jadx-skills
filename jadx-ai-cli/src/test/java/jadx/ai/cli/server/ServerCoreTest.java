package jadx.ai.cli.server;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jadx.api.JadxArgs;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for multi-APK session management in ServerCore.
 */
class ServerCoreTest {

	private ServerCore core;

	@BeforeEach
	void setUp() throws Exception {
		core = new ServerCore();
		core.start();
	}

	@AfterEach
	void tearDown() {
		if (core != null) {
			core.stop();
		}
	}

	@Test
	void testServerStartsAndStops() {
		assertTrue(core.isRunning());
		core.stop();
		assertFalse(core.isRunning());
	}

	@Test
	void testPingCommand() {
		CommandResult result = core.executeCommand("ping", new HashMap<>());
		assertTrue(result.isSuccess());
		assertEquals("pong", result.getData());
	}

	@Test
	void testStatusCommand() {
		CommandResult result = core.executeCommand("status", new HashMap<>());
		assertTrue(result.isSuccess());
		@SuppressWarnings("unchecked")
		Map<String, Object> status = (Map<String, Object>) result.getData();
		assertEquals("running", status.get("status"));
		assertEquals(0, status.get("sessionCount"));
	}

	@Test
	void testSessionListEmpty() {
		CommandResult result = core.executeCommand("session-list", new HashMap<>());
		assertTrue(result.isSuccess());
	}

	@Test
	void testCommandWithoutSessionReturnsError() {
		Map<String, Object> args = new HashMap<>();
		args.put("query", "Activity");
		args.put("type", "class");
		CommandResult result = core.executeCommand("search", args);
		assertFalse(result.isSuccess());
		assertTrue(result.getError().contains("No active session"));
	}

	@Test
	void testSessionOpenWithMissingPath() {
		Map<String, Object> args = new HashMap<>();
		args.put("inputPath", "/nonexistent/file.apk");
		CommandResult result = core.executeCommand("session-open", args);
		assertFalse(result.isSuccess());
		assertTrue(result.getError().contains("not found"));
	}

	@Test
	void testSessionOpenWithoutPath() {
		CommandResult result = core.executeCommand("session-open", new HashMap<>());
		assertFalse(result.isSuccess());
		assertTrue(result.getError().contains("inputPath is required"));
	}

	@Test
	void testSessionCloseWithoutId() {
		Map<String, Object> args = new HashMap<>();
		CommandResult result = core.executeCommand("session-close", args);
		assertFalse(result.isSuccess());
		assertTrue(result.getError().contains("sessionId is required"));
	}

	@Test
	void testUnknownCommand() {
		CommandResult result = core.executeCommand("nonexistent-command", new HashMap<>());
		assertFalse(result.isSuccess());
	}

	@Test
	void testShutdownCommand() {
		CommandResult result = core.executeCommand("shutdown", new HashMap<>());
		assertTrue(result.isSuccess());
		assertEquals("shutting down", result.getData());
	}
}
