package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the literal-form deepening of the {@code debugger} rule in
 * {@link TamperDetectionScanCommand}.
 *
 * <p>{@code ApplicationInfo.FLAG_DEBUGGABLE} (= 2) is a {@code static final int} constant, folded to
 * the integer literal by javac/d8, so jadx decompiles {@code (flags & FLAG_DEBUGGABLE) != 0} as
 * {@code (flags & 2) != 0} — the identifier NEVER appears. The old identifier-only arms were dead
 * for this form, so a pure FLAG_DEBUGGABLE check (with no {@code isDebuggerConnected()} call) was
 * missed. Verified against actual javac&#8594;d8&#8594;jadx output ({@code (flags & 2) != 0;}).
 */
class TamperDebuggerFlagDebuggableLiteralTest {

	// The debugger rule as the command compiles it.
	private static final java.util.regex.Pattern DEBUGGER = java.util.regex.Pattern.compile(
			"flags\\s*&\\s*2\\b|isDebuggerConnected\\s*\\(|waitingForDebugger\\s*\\(|ApplicationInfo\\.FLAG_DEBUGGABLE|FLAG_DEBUGGABLE|android\\.os\\.Debug|Debug\\.threadCpuTimeNanos");

	@Test
	void flagsBitwiseAnd2Fires() {
		assertTrue(DEBUGGER.matcher("return (getApplicationInfo().flags & 2) != 0;").find(),
				"(flags & 2) (FLAG_DEBUGGABLE) — the real jadx form — must fire");
	}

	@Test
	void flagsBitwiseAnd2WithSpacesFires() {
		assertTrue(DEBUGGER.matcher("boolean dbg = (flags  &  2) != 0;").find(),
				"(flags  &  2) with spaces must fire");
	}

	@Test
	void isDebuggerConnectedStillFires() {
		assertTrue(DEBUGGER.matcher("if (Debug.isDebuggerConnected()) {").find(),
				"isDebuggerConnected() must still fire");
	}

	@Test
	void identifierFormStillFires() {
		assertTrue(DEBUGGER.matcher("(flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0").find(),
				"the identifier form must still fire");
	}

	@Test
	void unrelatedBitwiseAndDoesNotFire() {
		assertFalse(DEBUGGER.matcher("(flags & 4) != 0").find(),
				"(flags & 4) (a different bit) must NOT fire the debugger rule");
	}

	@Test
	void bareTwoNotInFlagsExprDoesNotFire() {
		assertFalse(DEBUGGER.matcher("int x = 2;").find(),
				"a bare 2 NOT in a `flags & 2` expression must NOT fire");
	}
}
