package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the cross-line {@link FragmentInjectionScanCommand#FRAGMENT_FROM_INTENT_SPLIT} fix.
 *
 * <p>When the intent extra is read into a local that is REUSED (e.g. logged or passed twice),
 * jadx keeps the local and splits the two statements across lines — and renames the local after
 * its origin (e.g. {@code stringExtra}), so the second line reads
 * {@code Fragment.instantiate(this, stringExtra);} with NO {@code getStringExtra} token:
 * <pre>
 *   String stringExtra = getIntent().getStringExtra("fragment_class");  // getStringExtra, no instantiate
 *   Fragment.instantiate(this, stringExtra);                            // instantiate, no getStringExtra
 * </pre>
 * Every per-line arm of {@link FragmentInjectionScanCommand#FRAGMENT_FROM_INTENT} welds
 * {@code instantiate} and {@code getStringExtra}/{@code getIntent} with {@code .*} on one line,
 * so neither line matches — a silent HIGH-severity FN (attacker-controlled Fragment class). When
 * the extra is used ONCE jadx inlines it back to a single line (caught by the per-line arms);
 * {@code FRAGMENT_FROM_INTENT_SPLIT} (DOTALL) catches the reused-local split. Verified against real
 * javac&#8594;d8&#8594;jadx output.
 */
class FragmentInjectionSplitTest {

	private static final Pattern SPLIT = FragmentInjectionScanCommand.FRAGMENT_FROM_INTENT_SPLIT;

	@Test
	void crossLineExtraReusedLocalFires() {
		// The real jadx form (verified): extra read into a reused local, instantiate on the next line.
		String code = "String stringExtra = getIntent().getStringExtra(\"fragment_class\");\n"
				+ "Fragment.instantiate(this, stringExtra);\n"
				+ "System.out.println(stringExtra);";
		assertTrue(SPLIT.matcher(code).find(),
				"a Fragment.instantiate fed by an intent extra on a separate statement must fire (was a silent high FN)");
	}

	@Test
	void crossLineGetIntentThenInstantiateFires() {
		// getIntent() on line 1, Fragment.instantiate on a later line.
		String code = "Intent i = getIntent();\n" + "Fragment.instantiate(this, i.getStringExtra(\"f\"));";
		assertTrue(SPLIT.matcher(code).find(),
				"getIntent() followed by Fragment.instantiate must fire");
	}

	@Test
	void sameLineInlinedHandledByPerLineArmsNotSplit() {
		// When the extra is used once jadx inlines: `Fragment.instantiate(this, getIntent().getStringExtra("..."))`.
		// Here instantiate is BEFORE getStringExtra, so the split pattern (forward: extra→instantiate)
		// does NOT match — but the per-line FRAGMENT_FROM_INTENT arm
		// `Fragment.instantiate.*getStringExtra` DOES (instantiate then getStringExtra on one line),
		// and execute()'s reportedKinds dedups so the split fallback only runs when the per-line pass
		// found nothing. This documents the split pattern's directional scope, not a requirement.
		assertFalse(SPLIT.matcher("Fragment.instantiate(this, getIntent().getStringExtra(\"fragment_class\"));").find(),
				"the split pattern is forward-only (extra→instantiate); the same-line inlined form is handled by the per-line arms");
	}

	@Test
	void instantiateWithoutExtraDoesNotFire() {
		// Fragment.instantiate with a hardcoded class name — no getStringExtra/getIntent source.
		String code = "Fragment.instantiate(this, \"com.app.MyFragment\");";
		assertFalse(SPLIT.matcher(code).find(),
				"a Fragment.instantiate with a hardcoded class name and no intent-extra source must not fire");
	}

	@Test
	void extraWithoutInstantiateDoesNotFire() {
		// getStringExtra present but no Fragment.instantiate — not a fragment-injection sink.
		String code = "String x = getIntent().getStringExtra(\"fragment_class\");\n"
				+ "Log.d(TAG, x);";
		assertFalse(SPLIT.matcher(code).find(),
				"an intent extra read with no Fragment.instantiate must not fire");
	}
}
