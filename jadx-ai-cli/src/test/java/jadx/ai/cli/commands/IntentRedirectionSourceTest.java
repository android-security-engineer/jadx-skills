package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the array / array-list source coverage in {@link IntentRedirectionScanCommand}.
 *
 * <p>Before the fix, {@code INTENT_SOURCE} only matched {@code getParcelableExtra(} /
 * {@code getParcelable(}. An attacker can deliver a nested Intent as an element of a
 * {@code Parcelable[]} ({@code getParcelableArrayExtra}) or an {@code ArrayList<Parcelable>}
 * ({@code getParcelableArrayListExtra}) just as well as a single value, and the victim iterates and
 * launches it — but those sources were silently missed because {@code getParcelable\s*\(} does not
 * match {@code getParcelableArrayListExtra(} (the char after {@code getParcelable} is {@code A}, not
 * {@code (}). The class-level source gate would then skip the class entirely, dropping the redirect.
 */
class IntentRedirectionSourceTest {

	private static boolean sourceOn(String line) {
		return IntentRedirectionScanCommand.INTENT_SOURCE.matcher(line).find();
	}

	@Test
	void singleParcelableExtrasStillMatch() {
		assertTrue(sourceOn("Intent inner = (Intent) getIntent().getParcelableExtra(\"k\");"));
		assertTrue(sourceOn("Parcelable p = bundle.getParcelable(\"k\");"));
	}

	@Test
	void parcelableArrayExtraNowMatches() {
		assertTrue(sourceOn("Parcelable[] arr = intent.getParcelableArrayExtra(\"items\");"),
				"getParcelableArrayExtra is a real redirection source (smuggle Intent as array element)");
	}

	@Test
	void parcelableArrayListExtraNowMatches() {
		assertTrue(sourceOn("ArrayList<Parcelable> list = intent.getParcelableArrayListExtra(\"items\");"),
				"getParcelableArrayListExtra is a real redirection source (smuggle Intent in a list)");
	}

	@Test
	void intentParseUriStillMatches() {
		assertTrue(sourceOn("Intent parsed = Intent.parseUri(uri, 0);"));
	}

	@Test
	void nonParcelExtraDoesNotMatch() {
		assertFalse(sourceOn("String s = intent.getStringExtra(\"k\");"),
				"getStringExtra is not a nested-Intent source");
		assertFalse(sourceOn("int i = intent.getIntExtra(\"k\", 0);"),
				"getIntExtra is not a nested-Intent source");
	}

	@Test
	void getParcelableArrayListExtraNotConfusedWithBareGetParcelable() {
		// Regression guard: the array-list form must match on ITS OWN term, not by accident of the
		// bare getParcelable( regex (which would require a '(' right after getParcelable).
		assertTrue(sourceOn("getParcelableArrayListExtra(\"x\");"));
		assertTrue(sourceOn("getParcelableArrayExtra(\"x\");"));
	}
}
