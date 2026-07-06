package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the false-positive fix in {@link TrustBoundaryScanCommand#INTENT_AUTH}.
 *
 * <p>The old {@code getIntent.*role}/{@code getBooleanExtra.*login}/etc. arms paired an Intent getter
 * with any same-line substring, so a log line ({@code Log.d("intent=" + getIntent() + " role=" + getRole())})
 * was flagged {@code intent_auth_decision} <b>high</b>. Now the sensitive keyword must appear inside the
 * extra-NAME string literal of a {@code getXxxExtra("...")} call. Verified against real
 * javac&#8594;d8&#8594;jadx output.
 */
class TrustBoundaryIntentAuthFpTest {

	private static final java.util.regex.Pattern INTENT_AUTH = TrustBoundaryScanCommand.INTENT_AUTH;

	// --- false positives must NOT fire ---

	@Test
	void getIntentInLogWithRoleDoesNotFire() {
		assertFalse(INTENT_AUTH.matcher(
				"Log.d(\"TB\", \"intent=\" + String.valueOf(getIntent()) + \" role=\" + getUserRole());").find(),
				"a log line with getIntent() + role= must NOT fire (was a high FP)");
	}

	@Test
	void debugExtraDoesNotFire() {
		assertFalse(INTENT_AUTH.matcher(
				"if (getIntent().getBooleanExtra(\"debug\", false)) { enableLogging(); }").find(),
				"a non-auth \"debug\" extra must NOT fire");
	}

	@Test
	void harmlessExtraNameDoesNotFire() {
		assertFalse(INTENT_AUTH.matcher(
				"String title = getIntent().getStringExtra(\"title\");").find(),
				"a non-auth extra name must NOT fire");
	}

	// --- true positives still fire ---

	@Test
	void isAdminExtraFires() {
		assertTrue(INTENT_AUTH.matcher(
				"if (getIntent().getBooleanExtra(\"isAdmin\", false)) { enterAdminMode(); }").find(),
				"getBooleanExtra(\"isAdmin\", ...) — an attacker-controlled auth decision — must fire");
	}

	@Test
	void authLevelExtraFires() {
		assertTrue(INTENT_AUTH.matcher(
				"String role = getIntent().getStringExtra(\"auth_level\");").find(),
				"getStringExtra(\"auth_level\") must fire");
	}

	@Test
	void roleExtraFires() {
		assertTrue(INTENT_AUTH.matcher(
				"getIntent().getBooleanExtra(\"role\", false);").find(),
				"getBooleanExtra(\"role\", ...) must fire");
	}

	@Test
	void permissionBundleExtraFires() {
		assertTrue(INTENT_AUTH.matcher(
				"intent.getBundleExtra(\"permission\");").find(),
				"getBundleExtra(\"permission\") must fire");
	}
}
