package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the fix for a <b>false-positive-amplifying</b> dead-code regex in
 * {@link PendingIntentScanCommand}.
 *
 * <p>{@code PendingIntent.FLAG_IMMUTABLE} / {@code FLAG_MUTABLE} are {@code static final int}
 * constants, so javac/d8 fold them to their integer literals in the bytecode; jadx decompiles a
 * creator call as {@code PendingIntent.getActivity(..., 67108864)} — the identifier
 * {@code FLAG_IMMUTABLE} NEVER appears. The old pattern matched only the identifier, so
 * {@code hasImmutable} was <em>always false</em>: every PendingIntent — even an explicitly-IMMUTABLE
 * one — was flagged {@code implicitly_mutable_pending_intent} high. This is worse than a false
 * negative: it flags safe code as a high-severity finding.
 *
 * <p>{@link PendingIntentScanCommand#FLAG_IMMUTABLE} / {@link PendingIntentScanCommand#FLAG_MUTABLE}
 * now match the identifier OR the decimal literal OR the hex literal (FLAG_IMMUTABLE = 0x04000000,
 * FLAG_MUTABLE = 0x02000000), mirroring the already-correct {@code IntentScanCommand}.
 */
class PendingIntentImmutableLiteralTest {

	private static final java.util.regex.Pattern IMMUTABLE = PendingIntentScanCommand.FLAG_IMMUTABLE;
	private static final java.util.regex.Pattern MUTABLE = PendingIntentScanCommand.FLAG_MUTABLE;

	// --- FLAG_IMMUTABLE: decimal literal (the real jadx-decompiled form) ---

	@Test
	void immutableDecimalLiteralFires() {
		assertTrue(IMMUTABLE.matcher("PendingIntent.getActivity(context, 0, intent, 67108864);").find(),
				"the decompiled literal 67108864 (FLAG_IMMUTABLE) must be recognized — this is the form "
						+ "jadx actually emits; the old identifier-only pattern missed it and flagged safe code high");
	}

	@Test
	void immutableHexLiteralFires() {
		assertTrue(IMMUTABLE.matcher("PendingIntent.getActivity(context, 0, intent, 0x04000000);").find(),
				"the hex literal 0x04000000 must be recognized (jadx hex-output mode)");
	}

	@Test
	void immutableIdentifierStillFires() {
		assertTrue(IMMUTABLE.matcher("PendingIntent.getActivity(context, 0, intent, FLAG_IMMUTABLE);").find(),
				"the identifier form (rare — jadx normally folds it) must still fire");
	}

	// --- FLAG_MUTABLE ---

	@Test
	void mutableDecimalLiteralFires() {
		assertTrue(MUTABLE.matcher("PendingIntent.getActivity(context, 0, intent, 33554432);").find(),
				"the decompiled literal 33554432 (FLAG_MUTABLE) must be recognized");
	}

	@Test
	void mutableHexLiteralFires() {
		assertTrue(MUTABLE.matcher("PendingIntent.getActivity(context, 0, intent, 0x02000000);").find(),
				"the hex literal 0x02000000 must be recognized");
	}

	@Test
	void mutableIdentifierStillFires() {
		assertTrue(MUTABLE.matcher("pi = PendingIntent.getActivity(c, 0, i, FLAG_MUTABLE);").find(),
				"the identifier form must still fire");
	}

	// --- the false-positive-amplification case: explicit IMMUTABLE must NOT be mutable ---

	@Test
	void explicitImmutableArgIsNotMutable() {
		// This is the exact case the old dead-code pattern broke: a creator passed FLAG_IMMUTABLE as
		// the decompiled literal. hasImmutable must now be true so the call is NOT flagged.
		String args = "context, 0, intent, 67108864";
		assertTrue(PendingIntentScanCommand.FLAG_IMMUTABLE.matcher(args).find(),
				"hasImmutable must be true for a 67108864 flags arg");
		assertFalse(PendingIntentScanCommand.FLAG_MUTABLE.matcher(args).find(),
				"hasMutable must be false for a 67108864-only flags arg");
	}

	@Test
	void neitherFlagArgIsImplicitlyMutable() {
		// A bare 0 (no flag) — the implicitly-mutable case.
		String args = "context, 0, intent, 0";
		assertFalse(PendingIntentScanCommand.FLAG_IMMUTABLE.matcher(args).find(),
				"hasImmutable must be false for a bare-0 flags arg");
		assertFalse(PendingIntentScanCommand.FLAG_MUTABLE.matcher(args).find(),
				"hasMutable must be false for a bare-0 flags arg");
	}

	// --- the literals must not over-match arbitrary numbers ---

	@Test
	void unrelatedNumbersDoNotFire() {
		assertFalse(IMMUTABLE.matcher("int requestCode = 0;").find(),
				"a bare 0 must not fire the IMMUTABLE rule");
		assertFalse(MUTABLE.matcher("int x = 100;").find(),
				"an unrelated 100 must not fire the MUTABLE rule");
	}
}
