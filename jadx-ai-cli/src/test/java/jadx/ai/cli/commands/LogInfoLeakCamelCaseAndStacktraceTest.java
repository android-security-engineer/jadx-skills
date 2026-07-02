package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards two real-world log-leak shapes that {@link LogInfoLeakScanCommand} silently missed.
 *
 * <ol>
 *   <li><b>Case-insensitive matching</b> — Java/Android naming is camelCase ({@code privateKey},
 *       {@code accessToken}, {@code userToken}, {@code sessionKey}, {@code SecretKey}) and UPPER log
 *       tags ({@code Log.d("PASSWORD", ...)}). The keyword rules were case-sensitive (only
 *       underscore-lowercase {@code private_key}/{@code access_token}), so they missed the common
 *       Java identifier form. All rules now carry {@code (?i)}; zero new FP — only widens
 *       same-semantics word matching, mirroring {@code LoggingScanCommand.SENSITIVE} which was
 *       already {@code (?i)}.</li>
 *   <li><b>{@code printStackTrace()}</b> — writes the full stack trace and any exception message
 *       (which may carry SQL/path/secret-laden error text) to stderr/Logcat. It is an information-leak
 *       sink the sister {@code LoggingScanCommand.LOG_SINK} already listed, but
 *       {@code LogInfoLeakScanCommand.LOG_SINK_PREFIX} omitted it — so an {@code e.printStackTrace()}
 *       line bypassed the sink gate and every rule was skipped. Now in the sink set + a dedicated
 *       {@code log_stacktrace} info rule.</li>
 * </ol>
 */
class LogInfoLeakCamelCaseAndStacktraceTest {

	// --- 1. case-insensitive camelCase / UPPER forms ---

	@Test
	void camelCasePrivateKeyFires() {
		assertTrue(LogInfoLeakScanCommand.LOG_CRYPTO.matcher("Log.d(TAG, \"key=\" + privateKey);").find(),
				"camelCase privateKey must fire the crypto rule (was case-sensitive, missed it)");
	}

	@Test
	void camelCaseAccessTokenFires() {
		assertTrue(LogInfoLeakScanCommand.LOG_TOKEN.matcher("Log.d(TAG, \"val=\" + accessToken);").find(),
				"camelCase accessToken must fire the token rule");
	}

	@Test
	void camelCaseUserTokenFires() {
		assertTrue(LogInfoLeakScanCommand.LOG_TOKEN.matcher("Log.d(TAG, \"v=\" + userToken);").find(),
				"camelCase userToken must fire the token rule (uppercase T was missed)");
	}

	@Test
	void camelCaseSessionKeyFires() {
		assertTrue(LogInfoLeakScanCommand.LOG_CRYPTO.matcher("Log.d(TAG, \"k=\" + sessionKey);").find(),
				"camelCase sessionKey must fire the crypto rule");
	}

	@Test
	void upperTagPasswordFires() {
		assertTrue(LogInfoLeakScanCommand.LOG_PASSWORD.matcher("Log.d(\"PASSWORD\", \"loaded\");").find(),
				"an UPPER log tag PASSWORD must fire the password rule");
	}

	@Test
	void mixedCaseAuthorizationFires() {
		assertTrue(LogInfoLeakScanCommand.LOG_AUTH_HEADER.matcher("Log.d(TAG, \"h=\" + authorization);").find(),
				"lowercase authorization must fire the auth-header rule (was mixed-case only)");
	}

	@Test
	void lowerCaseStillFires() {
		// Regression guard: the (?i) change must not break the existing lowercase form.
		assertTrue(LogInfoLeakScanCommand.LOG_PASSWORD.matcher("Log.d(TAG, \"password=\" + pwd);").find(),
				"lowercase password must still fire");
	}

	// --- 2. printStackTrace sink + log_stacktrace rule ---

	@Test
	void printStackTraceIsASink() {
		assertTrue(LogInfoLeakScanCommand.LOG_CALL.matcher("e.printStackTrace();").find(),
				"printStackTrace() must be recognised as a log sink (it writes to stderr/Logcat)");
	}

	@Test
	void printStackTraceFiresStacktraceRule() {
		assertTrue(LogInfoLeakScanCommand.LOG_STACKTRACE.matcher("e.printStackTrace();").find(),
				"a printStackTrace call must fire the log_stacktrace rule");
	}

	@Test
	void printStackTraceFiresEvenWithoutKeyword() {
		// The whole point: a printStackTrace line has no password/token keyword, but it is still a
		// leak. The dedicated LOG_STACKTRACE rule fires where the keyword rules would all miss.
		assertFalse(LogInfoLeakScanCommand.LOG_PASSWORD.matcher("e.printStackTrace();").find(),
				"a bare printStackTrace has no password keyword — the keyword rule must NOT fire");
		assertTrue(LogInfoLeakScanCommand.LOG_STACKTRACE.matcher("e.printStackTrace();").find(),
				"but the dedicated log_stacktrace rule must fire");
	}

	@Test
	void nonStacktraceCallDoesNotFireStacktraceRule() {
		assertFalse(LogInfoLeakScanCommand.LOG_STACKTRACE.matcher("Log.d(TAG, \"done\");").find(),
				"a plain Log.d must NOT fire the log_stacktrace rule");
	}
}
