package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the gate-vs-rule symmetry fix in {@link InsecureDeeplinkHandlerScanCommand#DEEPLINK_MARKER}.
 *
 * <p>The gate lacked {@code getDataString}. jadx emits the variable form {@code intent.getDataString()}
 * (Intent stored in a local variable), which does NOT match {@code getData\s*\(} (followed by {@code S},
 * not {@code (}) nor {@code getIntent().getData} (it's {@code intent.}, not {@code getIntent().}).
 * A handler reading the raw URI string via a local Intent variable was skipped at the gate →
 * {@code deeplink_path_traversal}/{@code deeplink_sql_injection}/{@code deeplink_webview_load}/
 * {@code deeplink_auth_decision} <b>high</b> never fired. Verified against real javac&#8594;d8&#8594;jadx output.
 */
class InsecureDeeplinkHandlerGateGetDataStringTest {

	private static final java.util.regex.Pattern DEEPLINK_MARKER = InsecureDeeplinkHandlerScanCommand.DEEPLINK_MARKER;

	@Test
	void intentGetDataStringMatchesGate() {
		assertTrue(DEEPLINK_MARKER.matcher("new File(intent.getDataString());").find(),
				"intent.getDataString() (variable form) must match the gate (was skipped → high FN)");
	}

	@Test
	void getDataCallStillMatchesGate() {
		assertTrue(DEEPLINK_MARKER.matcher("Uri uri = getIntent().getData();").find(),
				"getData() (call form) must still match the gate");
	}

	@Test
	void getDataStringAssignedToVarMatchesGate() {
		assertTrue(DEEPLINK_MARKER.matcher("String u = intent.getDataString();").find(),
				"getDataString() assigned to a local must match the gate");
	}
}
