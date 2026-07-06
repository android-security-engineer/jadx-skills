package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the literal-form deepening of {@link TapjackingScanCommand}'s overlay-window and
 * FLAG_SECURE rules.
 *
 * <p>The overlay window-type constants ({@code TYPE_APPLICATION_OVERLAY}=2038, {@code TYPE_SYSTEM_ALERT}
 * =2003, {@code TYPE_SYSTEM_OVERLAY}=2006, {@code TYPE_SYSTEM_ERROR}=2010, {@code TYPE_PHONE}=2002)
 * and {@code FLAG_SECURE}=8192 are all {@code static final int} constants, folded to integer literals
 * by javac/d8. jadx therefore decompiles {@code params.type = TYPE_APPLICATION_OVERLAY} as
 * {@code params.type = 2038} and {@code setFlags(FLAG_SECURE, FLAG_SECURE)} as {@code setFlags(8192, 8192)}
 * — the identifiers NEVER appear. The old identifier-only arms were dead code on real decompiled
 * output: the {@code overlay_window} rule fired only on the rare {@code canDrawOverlays()} call, and
 * the {@code flag_secure} defence-inventory rule never fired at all. Verified against actual
 * javac&#8594;d8&#8594;jadx output ({@code layoutParams.type = 2038;}).
 */
class TapjackingOverlayLiteralTest {

	// Reconstruct the two rule patterns the way the command compiles them.
	private static final java.util.regex.Pattern OVERLAY = java.util.regex.Pattern.compile(
			"\\.type\\s*=\\s*(?:2038|2003|2006|2010|2002|2008|2009)\\b"
					+ "|TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|TYPE_SYSTEM_OVERLAY|TYPE_SYSTEM_ERROR|TYPE_PHONE\\b"
					+ "|canDrawOverlays\\s*\\(|SYSTEM_ALERT_WINDOW");
	private static final java.util.regex.Pattern FLAG_SECURE = java.util.regex.Pattern.compile(
			"setFlags\\s*\\([^)]*\\b8192\\b|addFlags\\s*\\(\\s*\\b8192\\b|FLAG_SECURE");

	// --- overlay_window: the real jadx-decompiled `.type = <literal>` form ---

	@Test
	void typeAssignmentLiteral2038Fires() {
		assertTrue(OVERLAY.matcher("layoutParams.type = 2038;").find(),
				"params.type = 2038 (TYPE_APPLICATION_OVERLAY) — the real jadx form — must fire");
	}

	@Test
	void typeAssignmentLiteral2003Fires() {
		assertTrue(OVERLAY.matcher("params.type = 2003;").find(),
				"params.type = 2003 (TYPE_SYSTEM_ALERT) must fire");
	}

	@Test
	void typeAssignmentLiteral2002Fires() {
		assertTrue(OVERLAY.matcher("params.type = 2002;").find(),
				"params.type = 2002 (TYPE_PHONE) must fire");
	}

	@Test
	void canDrawOverlaysStillFires() {
		assertTrue(OVERLAY.matcher("if (Settings.canDrawOverlays(context)) {").find(),
				"canDrawOverlays() — the runtime overlay-permission check — must still fire");
	}

	@Test
	void identifierFormStillFires() {
		assertTrue(OVERLAY.matcher("params.type = WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY;").find(),
				"the identifier form (source-form code) must still fire");
	}

	@Test
	void unrelatedTypeLiteralDoesNotFire() {
		// A non-overlay type literal (e.g. TYPE_INPUT_METHOD = 2011) must not fire.
		assertFalse(OVERLAY.matcher("params.type = 2011;").find(),
				"a non-overlay .type assignment must NOT fire");
	}

	@Test
	void bare2038DoesNotFire() {
		// A bare 2038 not in a `.type =` assignment (and not canDrawOverlays/SYSTEM_ALERT_WINDOW).
		assertFalse(OVERLAY.matcher("int x = 2038;").find(),
				"a bare 2038 assignment is not an overlay-type assignment — must not fire");
	}

	// --- flag_secure: setFlags(8192, 8192) ---

	@Test
	void setFlagsLiteral8192Fires() {
		assertTrue(FLAG_SECURE.matcher("getWindow().setFlags(8192, 8192);").find(),
				"setFlags(8192, 8192) — the decompiled FLAG_SECURE form — must fire the defence rule");
	}

	@Test
	void identifierFlagSecureStillFires() {
		assertTrue(FLAG_SECURE.matcher("setFlags(FLAG_SECURE, FLAG_SECURE);").find(),
				"the identifier form must still fire");
	}

	@Test
	void unrelatedSetFlagsDoesNotFire() {
		assertFalse(FLAG_SECURE.matcher("getWindow().setFlags(1024, 1024);").find(),
				"setFlags(1024, 1024) (FULLSCREEN) must NOT fire the FLAG_SECURE rule");
	}
}
