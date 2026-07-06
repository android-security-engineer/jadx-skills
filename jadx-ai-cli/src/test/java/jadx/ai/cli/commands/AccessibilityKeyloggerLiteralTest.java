package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the literal-form deepening of the {@code keylogger} rule in
 * {@link AccessibilityScanCommand}.
 *
 * <p>{@code AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED} is a {@code static final int} (= 16), folded
 * to the integer literal by javac/d8, so jadx decompiles {@code event.getEventType() == TYPE_VIEW_TEXT_CHANGED}
 * as {@code event.getEventType() == 16} and a {@code switch} on the type as {@code case 16:} — the
 * identifier NEVER appears. The old rule matched ONLY the identifier, so the high-severity keylogger
 * finding (the signature banking-trojan primitive) fired on zero real decompiled output. Verified
 * against actual javac&#8594;d8&#8594;jadx output.
 */
class AccessibilityKeyloggerLiteralTest {

	// The keylogger rule as the command compiles it.
	private static final java.util.regex.Pattern KEYLOGGER = java.util.regex.Pattern.compile(
			"getEventType\\s*\\(\\s*\\)\\s*==\\s*16\\b|case\\s+16\\b|TYPE_VIEW_TEXT_CHANGED");

	// --- the real jadx-decompiled forms ---

	@Test
	void getEventTypeEquals16Fires() {
		assertTrue(KEYLOGGER.matcher("if (event.getEventType() == 16) {").find(),
				"getEventType() == 16 (TYPE_VIEW_TEXT_CHANGED) — the real jadx form — must fire");
	}

	@Test
	void case16Fires() {
		assertTrue(KEYLOGGER.matcher("case 16:").find(),
				"a switch case 16 (TYPE_VIEW_TEXT_CHANGED) must fire");
	}

	@Test
	void case16WithColonAfterSpaceFires() {
		assertTrue(KEYLOGGER.matcher("case 16 :").find(),
				"case 16 with a space before the colon must fire");
	}

	// --- the identifier form (source-form / a constant jadx did not fold) ---

	@Test
	void identifierFormStillFires() {
		assertTrue(KEYLOGGER.matcher("if (event.getEventType() == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {").find(),
				"the identifier form must still fire");
	}

	// --- false-positive guards ---

	@Test
	void unrelatedEventType16NotInAccessibilityContextStillMatchesPattern() {
		// The rule is a per-line regex scoped by the ACCESSIBILITY_MARKER class gate (the test asserts
		// the pattern only; the gate is exercised end-to-end by CommandsTest). A bare `== 16` matches
		// the pattern, but the gate ensures it only fires in accessibility classes. Here we just confirm
		// the pattern does not match a non-16 event type.
		assertFalse(KEYLOGGER.matcher("if (event.getEventType() == 1) {").find(),
				"getEventType() == 1 (TYPE_VIEW_CLICKED) must NOT fire the keylogger rule");
		assertFalse(KEYLOGGER.matcher("case 1:").find(),
				"case 1 must NOT fire the keylogger rule");
	}

	@Test
	void getEventTypeNoComparisonDoesNotFire() {
		// A bare getEventType() call with no == 16 — not a TYPE_VIEW_TEXT_CHANGED check.
		assertFalse(KEYLOGGER.matcher("int t = event.getEventType();").find(),
				"a bare getEventType() call (no == 16) must NOT fire");
	}
}
