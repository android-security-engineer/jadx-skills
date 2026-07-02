package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the false-positive fix in {@link InsecureApiScanCommand#KEYGUARD_DISMISS}.
 *
 * <p>{@code KeyguardManager.isKeyguardLocked()} is a read-only boolean query ("is the keyguard
 * currently showing?") — it does NOT bypass the lock screen. The old rule matched it and flagged
 * every app that checks lock state (e.g. to decide whether to show a lock-screen notification) as
 * {@code keyguard_dismiss} <b>high</b>. Only the dismiss APIs ({@code dismissKeyguard} /
 * {@code requestDismissKeyguard}) actually bypass the lock.
 */
class InsecureApiKeyguardDismissFpTest {

	private static final java.util.regex.Pattern KEYGUARD_DISMISS = InsecureApiScanCommand.KEYGUARD_DISMISS;

	@Test
	void isKeyguardLockedReadQueryDoesNotFire() {
		assertFalse(KEYGUARD_DISMISS.matcher("if (km.isKeyguardLocked()) showLockScreen();").find(),
				"isKeyguardLocked() is a read-only query, not a bypass — must NOT fire");
	}

	@Test
	void dismissKeyguardFires() {
		assertTrue(KEYGUARD_DISMISS.matcher("km.dismissKeyguard(null, null);").find(),
				"dismissKeyguard() is the actual bypass — must fire");
	}

	@Test
	void requestDismissKeyguardFires() {
		assertTrue(KEYGUARD_DISMISS.matcher("activity.requestDismissKeyguard(a, 0);").find(),
				"requestDismissKeyguard() is the modern bypass API — must fire");
	}

	@Test
	void isKeyguardSecureDoesNotFire() {
		// isKeyguardSecure() is also a read-only query
		assertFalse(KEYGUARD_DISMISS.matcher("boolean secure = km.isKeyguardSecure();").find(),
				"isKeyguardSecure() is a read-only query — must NOT fire");
	}
}
