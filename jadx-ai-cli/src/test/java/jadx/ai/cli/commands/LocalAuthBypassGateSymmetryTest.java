package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the gate-vs-rule symmetry fix in {@link LocalAuthBypassScanCommand#AUTH_MARKER}.
 *
 * <p>The gate was missing the AUTH_METHOD anchors {@code isUnlocked}/{@code isUserAuthenticated}/
 * {@code isSessionValid}/{@code checkAuth}/{@code validateAuth}/{@code verifyAuth}/{@code isAuth}.
 * A backdoor method {@code public boolean isUserAuthenticated() { return true; }} (no biometric/
 * fingerprint reference) matched no gate token → the class was skipped → {@code auth_returns_true}
 * <b>high</b> never fired. Verified against real javac&#8594;d8&#8594;jadx output.
 */
class LocalAuthBypassGateSymmetryTest {

	private static final java.util.regex.Pattern AUTH_MARKER = LocalAuthBypassScanCommand.AUTH_MARKER;

	@Test
	void isUserAuthenticatedMatchesGate() {
		assertTrue(AUTH_MARKER.matcher("public boolean isUserAuthenticated() { return true; }").find(),
				"isUserAuthenticated() — a backdoor auth-bypass method — must match the gate (was skipped → high FN)");
	}

	@Test
	void isSessionValidMatchesGate() {
		assertTrue(AUTH_MARKER.matcher("public boolean isSessionValid() { return \"x\".equals(\"x\"); }").find(),
				"isSessionValid() must match the gate");
	}

	@Test
	void isUnlockedMatchesGate() {
		assertTrue(AUTH_MARKER.matcher("boolean unlocked = isUnlocked();").find(),
				"isUnlocked() must match the gate");
	}

	@Test
	void checkAuthMatchesGate() {
		assertTrue(AUTH_MARKER.matcher("if (checkAuth(input)) { grant(); }").find(),
				"checkAuth() must match the gate");
	}
}
