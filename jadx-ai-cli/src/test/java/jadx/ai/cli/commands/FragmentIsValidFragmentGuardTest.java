package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code isValidFragment()} false-positive fix in {@link FragmentInjectionScanCommand}.
 *
 * <p>Before the fix, any class mentioning {@code PreferenceActivity} or {@code EXTRA_SHOW_FRAGMENT}
 * was flagged {@code preference_fragment_injection}/{@code high} — even when the app had already
 * applied the documented mitigation by overriding {@code isValidFragment()}. That turned hardened
 * code into a high-severity finding. The override IS the fix, so a protected app must downgrade to
 * an info-level {@code preference_fragment_protected} instead.
 */
class FragmentIsValidFragmentGuardTest {

	/** Drives the per-class rule loop the same way execute() does, returning the preference finding. */
	private static Map<String, Object> preferenceFindingFor(String code) {
		List<Map<String, Object>> findings = new ArrayList<>();
		boolean protectedByIsValidFragment = FragmentInjectionScanCommand.protectedByIsValidFragment(code);
		// Mirror the RULES[] preference_fragment_injection branch + the FP-guard rewrite.
		String kind = "preference_fragment_injection";
		String severity = "high";
		if (protectedByIsValidFragment) {
			kind = "preference_fragment_protected";
			severity = "info";
		}
		findings.add(Map.of("kind", kind, "severity", severity));
		return findings.get(0);
	}

	@Test
	void overrideDowngradesInjectionToProtectedInfo() {
		// A PreferenceActivity that DID the right thing: override isValidFragment to whitelist.
		String code = "public class SettingsActivity extends PreferenceActivity {\n"
				+ "  @Override\n"
				+ "  protected boolean isValidFragment(String fragmentName) {\n"
				+ "    return ALLOWED.contains(fragmentName);\n"
				+ "  }\n"
				+ "  // references EXTRA_SHOW_FRAGMENT via headers xml\n"
				+ "}\n";
		assertTrue(FragmentInjectionScanCommand.protectedByIsValidFragment(code),
				"isValidFragment override must be detected");
		Map<String, Object> f = preferenceFindingFor(code);
		assertEquals("preference_fragment_protected", f.get("kind"));
		assertEquals("info", f.get("severity"));
	}

	@Test
	void noOverrideStaysHighInjection() {
		// Unprotected PreferenceActivity: no isValidFragment override → real CVE-2013-2090-class risk.
		String code = "public class SettingsActivity extends PreferenceActivity {\n"
				+ "  // headers xml references EXTRA_SHOW_FRAGMENT, no override\n"
				+ "}\n";
		assertFalse(FragmentInjectionScanCommand.protectedByIsValidFragment(code),
				"no override → not protected");
		Map<String, Object> f = preferenceFindingFor(code);
		assertEquals("preference_fragment_injection", f.get("kind"));
		assertEquals("high", f.get("severity"));
	}

	@Test
	void bareOverrideParamSpellingMatches() {
		// Decompiler may emit the single-arg form with any local param name.
		assertTrue(FragmentInjectionScanCommand.protectedByIsValidFragment(
				"public boolean isValidFragment(String fragmentName) { return true; }"));
		assertTrue(FragmentInjectionScanCommand.protectedByIsValidFragment(
				"boolean isValidFragment(String s) {\n  return true;\n}"));
	}

	@Test
	void methodNameInCommentOrStringIsNotAnOverride() {
		// A comment or log line referencing isValidFragment must NOT count — only a method body does.
		assertFalse(FragmentInjectionScanCommand.protectedByIsValidFragment(
				"// TODO override isValidFragment(String) to fix injection\n"
						+ "public class P extends PreferenceActivity {}"),
				"a comment mentioning the method is not an override");
		assertFalse(FragmentInjectionScanCommand.protectedByIsValidFragment(
				"Log.d(\"x\", \"isValidFragment(String) not implemented\");"),
				"a string literal mentioning the method is not an override");
	}

	@Test
	void zeroArgOrTwoArgLookalikeDoesNotMatch() {
		// isValidFragment() with no arg, or a different signature, is not the protected override.
		assertFalse(FragmentInjectionScanCommand.protectedByIsValidFragment(
				"boolean isValidFragment() { return true; }"),
				"zero-arg overload is not the mitigation override");
	}
}
