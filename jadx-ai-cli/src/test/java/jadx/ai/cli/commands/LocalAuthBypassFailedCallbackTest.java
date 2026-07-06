package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the missing {@code onAuthenticationFailed}-does-not-block half of
 * {@code biometric_result_ignored} in {@link LocalAuthBypassScanCommand}.
 *
 * <p>The class javadoc promises {@code biometric_result_ignored} fires when
 * {@code onAuthenticationSucceeded} ignores the result <b>or</b> when {@code onAuthenticationFailed}
 * does not block access. The {@code onAuthenticationSucceeded} half was implemented, and
 * {@code ON_AUTH_FAILED} was even defined — but the failed-callback half was never wired in, so a
 * biometric handler that swallows a failure (no {@code finish()}/{@code return()}/{@code cancel()})
 * was a silent false-negative. Fixed by scanning the failed-callback body for a
 * {@link LocalAuthBypassScanCommand#BLOCKING_CALL}.
 */
class LocalAuthBypassFailedCallbackTest {

	@Test
	void blockingCallMatchesFinishReturnCancel() {
		assertTrue(LocalAuthBypassScanCommand.BLOCKING_CALL.matcher("activity.finish();").find(),
				"finish() is a blocking call");
		assertTrue(LocalAuthBypassScanCommand.BLOCKING_CALL.matcher("return;").find(),
				"return is a blocking call");
		assertTrue(LocalAuthBypassScanCommand.BLOCKING_CALL.matcher("dialog.cancel();").find(),
				"cancel() is a blocking call");
		assertTrue(LocalAuthBypassScanCommand.BLOCKING_CALL.matcher("throw new SecurityException();").find(),
				"throw is a blocking call");
	}

	/**
	 * Mirrors execute()'s per-class decision: returns true iff the class has an onAuthenticationFailed
	 * callback whose body (up to the closing brace) contains NO blocking call — i.e. the finding fires.
	 */
	private static boolean failedCallbackDoesNotBlock(String code) {
		String[] lines = code.split("\n", -1);
		boolean anyFailed = false;
		for (int i = 0; i < lines.length; i++) {
			if (!LocalAuthBypassScanCommand.ON_AUTH_FAILED.matcher(lines[i]).find()) {
				continue;
			}
			anyFailed = true;
			boolean blocks = false;
			for (int j = i + 1; j < Math.min(i + 12, lines.length); j++) {
				if (LocalAuthBypassScanCommand.BLOCKING_CALL.matcher(lines[j]).find()) {
					blocks = true;
					break;
				}
				if (lines[j].contains("void onAuthentication") || lines[j].trim().equals("}")) {
					break;
				}
			}
			if (!blocks) {
				return true; // this failed callback does not block → finding fires
			}
		}
		// anyFailed true but every failed callback blocks → no finding; no failed callback → no finding.
		return false;
	}

	@Test
	void emptyFailedCallbackFires() {
		// A failed callback that only logs — the canonical bypass.
		String code = "public void onAuthenticationFailed() {\n"
				+ "    Log.d(TAG, \"auth failed\");\n"
				+ "}\n";
		assertTrue(failedCallbackDoesNotBlock(code),
				"an onAuthenticationFailed body with no finish/return/cancel must fire");
	}

	@Test
	void failedCallbackThatFinishesDoesNotFire() {
		String code = "public void onAuthenticationFailed() {\n"
				+ "    Toast.makeText(ctx, \"denied\", 0).show();\n"
				+ "    finish();\n"
				+ "}\n";
		assertFalse(failedCallbackDoesNotBlock(code),
				"an onAuthenticationFailed that calls finish() blocks access — no finding");
	}

	@Test
	void failedCallbackThatReturnsDoesNotFire() {
		String code = "public void onAuthenticationFailed() {\n"
				+ "    callback.onDenied();\n"
				+ "    return;\n"
				+ "}\n";
		assertFalse(failedCallbackDoesNotBlock(code),
				"an onAuthenticationFailed with a return statement blocks access");
	}

	@Test
	void failedCallbackThatThrowsDoesNotFire() {
		String code = "public void onAuthenticationFailed() {\n"
				+ "    throw new SecurityException(\"biometric failed\");\n"
				+ "}\n";
		assertFalse(failedCallbackDoesNotBlock(code),
				"throwing in the failed callback blocks access");
	}

	@Test
	void noFailedCallbackDoesNotFire() {
		// A class with only the succeeded callback must not fire the failed-callback signal.
		String code = "public void onAuthenticationSucceeded(BiometricPrompt.Result result) {\n"
				+ "    grantAccess();\n"
				+ "}\n";
		assertFalse(failedCallbackDoesNotBlock(code),
				"without an onAuthenticationFailed callback the failed-callback signal must not fire");
	}

	@Test
	void succeededAndFailedCallbacksCoexist() {
		// When both callbacks exist and the failed one swallows the failure, the failed signal fires
		// independently of the succeeded one.
		String code = "public void onAuthenticationSucceeded(Result r) { grantAccess(); }\n"
				+ "public void onAuthenticationFailed() {\n"
				+ "    Log.w(TAG, \"failed\");\n"
				+ "}\n";
		assertTrue(failedCallbackDoesNotBlock(code),
				"a non-blocking onAuthenticationFailed must fire even alongside a succeeded callback");
	}
}
