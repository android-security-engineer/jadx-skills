package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the literal-form deepening of {@link ScreenshotLeakScanCommand#SENSITIVE_VIEW}.
 *
 * <p>{@code InputType.TYPE_TEXT_VARIATION_PASSWORD} (=128) and {@code TYPE_CLASS_TEXT} (=1) are
 * {@code static final int} constants, folded by javac/d8, so jadx decompiles
 * {@code setInputType(TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD)} as {@code setInputType(129)}
 * and the identifiers NEVER appear. The old identifier-only arms were dead code on decompiled
 * output — a password field set up the standard way was not recognized as a sensitive view.
 * Verified against actual javac&#8594;d8&#8594;jadx output ({@code setInputType(129);} / {@code setInputType(18);}).
 */
class ScreenshotLeakSensitiveViewLiteralTest {

	private static final java.util.regex.Pattern SENSITIVE_VIEW = ScreenshotLeakScanCommand.SENSITIVE_VIEW;

	// --- the real jadx-decompiled literal forms ---

	@Test
	void setInputType129Fires() {
		assertTrue(SENSITIVE_VIEW.matcher("editText.setInputType(129);").find(),
				"setInputType(129) (TYPE_CLASS_TEXT|TYPE_TEXT_VARIATION_PASSWORD) — the real jadx form — must fire");
	}

	@Test
	void setInputType18Fires() {
		assertTrue(SENSITIVE_VIEW.matcher("editText.setInputType(18);").find(),
				"setInputType(18) (TYPE_CLASS_NUMBER|TYPE_NUMBER_VARIATION_PASSWORD) must fire");
	}

	// --- identifier arms remain (source-form) ---

	@Test
	void identifierFormStillFires() {
		assertTrue(SENSITIVE_VIEW.matcher(
				"et.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);").find(),
				"the identifier form must still fire");
		assertTrue(SENSITIVE_VIEW.matcher("et.setInputType(TYPE_TEXT_VARIATION_PASSWORD);").find(),
				"the bare-identifier form must still fire");
	}

	// --- non-password input types must NOT fire ---

	@Test
	void setInputTypePlainTextDoesNotFire() {
		assertFalse(SENSITIVE_VIEW.matcher("et.setInputType(1);").find(),
				"setInputType(1) (TYPE_CLASS_TEXT, plain) must NOT fire");
	}

	@Test
	void setInputTypeNumberDoesNotFire() {
		assertFalse(SENSITIVE_VIEW.matcher("et.setInputType(2);").find(),
				"setInputType(2) (TYPE_CLASS_NUMBER, plain) must NOT fire");
	}

	// --- the EditText/password text arms stay ---

	@Test
	void editTextPasswordArmStillFires() {
		assertTrue(SENSITIVE_VIEW.matcher("EditText passwordField = findViewById(...);").find(),
				"the EditText.*password arm must still fire");
		assertTrue(SENSITIVE_VIEW.matcher("passwordInput.setText(\"\");").find(),
				"the passwordInput arm must still fire");
	}
}
