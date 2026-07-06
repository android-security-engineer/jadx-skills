package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code ACCT_MARKER} gate / RULES-set symmetry in {@link AccountScanCommand}.
 *
 * <p>execute() skips any class that does not match {@code ACCT_MARKER}, so every rule's anchor must
 * also appear in the gate. The gate was out of sync: {@code addPeriodicSync} and
 * {@code setSyncAutomatically} (the {@code acct_sync} rule) are {@code ContentResolver} static
 * methods usable with NO {@code AccountManager} and NO {@code ContentResolver.requestSync} in the
 * class, so a pure periodic-sync class was skipped and {@code acct_sync} never fired. The same
 * gate-vs-rule asymmetry held for {@code addAccountExplicitly}, {@code invalidateAuthToken}, and
 * {@code getAuthToken}/{@code blockingGetAuthToken}.
 */
class AccountGateSymmetryTest {

	private static boolean gated(String code) {
		return AccountScanCommand.ACCT_MARKER.matcher(code).find();
	}

	@Test
	void addPeriodicSyncClassPassesGate() {
		assertTrue(gated("ContentResolver.addPeriodicSync(authority, extras, 60);"),
				"addPeriodicSync must be in the gate — a pure periodic-sync class (no AccountManager) must not be skipped");
	}

	@Test
	void setSyncAutomaticallyClassPassesGate() {
		assertTrue(gated("ContentResolver.setSyncAutomatically(account, authority, true);"),
				"setSyncAutomatically must be in the gate — a pure sync-toggle class must not be skipped");
	}

	@Test
	void addAccountExplicitlyClassPassesGate() {
		assertTrue(gated("am.addAccountExplicitly(account, password, userdata);"),
				"addAccountExplicitly must be in the gate (regression guard for the acct_add_account rule)");
	}

	@Test
	void invalidateAuthTokenClassPassesGate() {
		assertTrue(gated("am.invalidateAuthToken(accountType, token);"),
				"invalidateAuthToken must be in the gate (regression guard for the acct_auth_token rule)");
	}

	@Test
	void getAuthTokenClassPassesGate() {
		assertTrue(gated("String t = am.getAuthToken(account, authType, options);"),
				"getAuthToken must be in the gate (regression guard for the acct_get_token rule)");
	}

	@Test
	void coreAccountManagerStillGated() {
		assertTrue(gated("AccountManager am = (AccountManager) getSystemService(ACCOUNT_SERVICE);"),
				"AccountManager must remain gated (regression guard)");
		assertTrue(gated("Account[] a = am.getAccounts();"),
				"getAccounts must remain gated (regression guard)");
	}
}
