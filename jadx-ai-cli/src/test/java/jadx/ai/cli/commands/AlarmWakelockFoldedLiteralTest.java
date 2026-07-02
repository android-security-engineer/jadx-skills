package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the constant-fold arm of {@link AlarmWakelockScanCommand#WAKELOCK_PARTIAL}.
 *
 * <p>{@code PowerManager.PARTIAL_WAKE_LOCK} is a {@code static final int} (=0x00000001) that
 * javac/d8 folds to the integer literal {@code 1}. jadx therefore emits
 * {@code newWakeLock(1, "tag")} — the identifier {@code PARTIAL_WAKE_LOCK} never appears in the
 * decompiled output. Without the {@code newWakeLock\s*\(\s*1\b} arm, every real decompiled
 * wakelock is a silent FN (the wakelock_partial rule's two identifier arms both miss). Verified
 * against real javac&#8594;d8&#8594;jadx output:
 * <pre>
 *   PowerManager.WakeLock w1 = new PowerManager().newWakeLock(1, "tag");
 * </pre>
 */
class AlarmWakelockFoldedLiteralTest {

	private static final Pattern WAKELOCK_PARTIAL = AlarmWakelockScanCommand.WAKELOCK_PARTIAL;

	@Test
	void foldedIntegerLiteralFires() {
		// The real jadx form: PARTIAL_WAKE_LOCK constant-folded to `1`.
		assertTrue(WAKELOCK_PARTIAL.matcher("PowerManager.WakeLock w1 = new PowerManager().newWakeLock(1, \"tag\");").find(),
				"a constant-folded newWakeLock(1, ...) — the real decompiled form — must fire (was a silent FN)");
	}

	@Test
	void foldedLiteralAtCallStartFires() {
		assertTrue(WAKELOCK_PARTIAL.matcher("newWakeLock(1, \"MyTag\").acquire();").find(),
				"newWakeLock(1 immediately after the paren must fire");
	}

	@Test
	void identifierFormStillFires() {
		assertTrue(WAKELOCK_PARTIAL.matcher("newWakeLock(PARTIAL_WAKE_LOCK, \"tag\");").find(),
				"the identifier form (un-folded, e.g. debug builds / non-d8) must still fire");
	}

	@Test
	void bareIdentifierFires() {
		assertTrue(WAKELOCK_PARTIAL.matcher("int flag = PARTIAL_WAKE_LOCK;").find(),
				"the bare PARTIAL_WAKE_LOCK identifier must still fire");
	}

	@Test
	void unrelatedWakeLockCallDoesNotFire() {
		// A wakelock acquired with a different flag value (e.g. 6 = ACQUIRE_CAUSES_WAKEUP|ON_AFTER_RELEASE)
		// is NOT a partial wake lock — must not fire.
		assertFalse(WAKELOCK_PARTIAL.matcher("newWakeLock(6, \"tag\");").find(),
				"a non-partial flag value must not fire the partial-wakelock rule");
	}

	@Test
	void newWakeLockWordWithoutLiteralOneDoesNotFire() {
		// `newWakeLock` alone (no arg shown) must not fire the folded arm — the `1` anchor is required.
		assertFalse(WAKELOCK_PARTIAL.matcher("PowerManager.WakeLock wl = pm.newWakeLock();").find(),
				"newWakeLock() with no folded `1` arg must not fire the folded arm");
	}
}
