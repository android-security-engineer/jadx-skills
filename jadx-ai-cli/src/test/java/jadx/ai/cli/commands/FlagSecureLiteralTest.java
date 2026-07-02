package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the literal-8192 deepening of {@code FLAG_SECURE} detection in
 * {@link ScreenCaptureScanCommand} and {@link ScreenshotLeakScanCommand}.
 *
 * <p>{@code WindowManager.LayoutParams.FLAG_SECURE} is a {@code static final int} (= 8192 = 0x2000),
 * so javac/d8 fold it to the integer literal; jadx decompiles the call as
 * {@code setFlags(8192, 8192)} / {@code addFlags(8192)} and the identifier {@code FLAG_SECURE}
 * usually does NOT appear. The old identifier-only patterns made {@code hasFlagSecure} /
 * {@code classHasFlagSecure} always false on real decompiled output — a false-positive amplifier
 * that flagged even defended Activities as {@code flag_secure_absent} /
 * {@code flag_secure_missing} high. Now the literal-8192 form (within a setFlags/addFlags call) is
 * matched. Verified against actual javac&#8594;d8&#8594;jadx output
 * ({@code getWindow().setFlags(8192, 8192)}).
 */
class FlagSecureLiteralTest {

	private static final java.util.regex.Pattern ON_WINDOW = ScreenCaptureScanCommand.FLAG_SECURE_ON_WINDOW;
	private static final java.util.regex.Pattern SET = ScreenshotLeakScanCommand.FLAG_SECURE_SET;
	private static final java.util.regex.Pattern CLEARED = ScreenshotLeakScanCommand.FLAG_SECURE_CLEARED;

	// --- setFlags(8192, 8192): the real jadx-decompiled FLAG_SECURE form ---

	@Test
	void setFlagsLiteral8192FiresOnWindow() {
		assertTrue(ON_WINDOW.matcher("getWindow().setFlags(8192, 8192);").find(),
				"setFlags(8192, 8192) — the real jadx-decompiled FLAG_SECURE form — must fire");
	}

	@Test
	void addFlagsLiteral8192FiresOnWindow() {
		assertTrue(ON_WINDOW.matcher("getWindow().addFlags(8192);").find(),
				"addFlags(8192) must fire");
	}

	@Test
	void setFlagsLiteral8192FiresSet() {
		assertTrue(SET.matcher("getWindow().setFlags(8192, 8192);").find(),
				"ScreenshotLeak FLAG_SECURE_SET must recognize the literal form");
	}

	@Test
	void identifierFormStillFiresOnWindow() {
		// Source-form / a constant jadx did not fold — the identifier arms remain.
		assertTrue(ON_WINDOW.matcher("getWindow().setFlags(FLAG_SECURE, FLAG_SECURE);").find(),
				"the identifier form must still fire (source-form code)");
		assertTrue(ON_WINDOW.matcher("getWindow().addFlags(FLAG_SECURE);").find(),
				"addFlags(FLAG_SECURE) identifier form must still fire");
	}

	// --- the false-positive-amplification case: a defended Activity must NOT be flagged absent ---

	@Test
	void defendedActivityLiteralNotAbsent() {
		// This is the case the old dead-code pattern broke: an Activity that DID set FLAG_SECURE, but
		// decompiled to the literal. classHasFlagSecure must now be true.
		String code = "public class X extends Activity {\n"
				+ "  void f(){ getWindow().setFlags(8192, 8192); }\n"
				+ "}\n";
		boolean classIsActivity = ScreenCaptureScanCommand.ACTIVITY_MARKER.matcher(code).find();
		boolean classHasFlagSecure = ScreenCaptureScanCommand.FLAG_SECURE_ON_WINDOW.matcher(code).find();
		assertTrue(classIsActivity, "the class is an Activity");
		assertTrue(classHasFlagSecure, "setFlags(8192, 8192) must count as defended — the literal form");
	}

	// --- bare 8192 (not a setFlags/addFlags call) must NOT false-positive ---

	@Test
	void bare8192DoesNotFireOnWindow() {
		assertFalse(ON_WINDOW.matcher("int mask = 8192;").find(),
				"a bare 8192 assignment is not a FLAG_SECURE application — must not fire");
		assertFalse(ON_WINDOW.matcher("return 8192;").find(),
				"a bare 8192 return is not a FLAG_SECURE application");
	}

	@Test
	void setFlagsWithout8192DoesNotFireOnWindow() {
		// setFlags with a different flag (e.g. FLAG_FULLSCREEN = 1024) is not FLAG_SECURE.
		assertFalse(ON_WINDOW.matcher("getWindow().setFlags(1024, 1024);").find(),
				"setFlags(1024, 1024) (FULLSCREEN) must NOT fire the FLAG_SECURE rule");
	}

	// --- FLAG_SECURE_CLEARED: clearFlags(8192) ---

	@Test
	void clearFlagsLiteral8192FiresCleared() {
		assertTrue(CLEARED.matcher("getWindow().clearFlags(8192);").find(),
				"clearFlags(8192) — removing FLAG_SECURE — must fire the cleared rule");
	}

	@Test
	void setFlagsZeroMaskFiresCleared() {
		assertTrue(CLEARED.matcher("getWindow().setFlags(0, 8192);").find(),
				"setFlags(0, 8192) — masking out FLAG_SECURE — must fire the cleared rule");
	}

	@Test
	void clearFlagsUnrelatedDoesNotFireCleared() {
		assertFalse(CLEARED.matcher("getWindow().clearFlags(1024);").find(),
				"clearFlags(1024) (a different flag) must NOT fire the FLAG_SECURE-cleared rule");
	}
}
