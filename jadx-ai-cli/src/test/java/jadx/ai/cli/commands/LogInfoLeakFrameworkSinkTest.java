package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the Timber / Logger framework-log classification in {@link LogInfoLeakScanCommand}.
 *
 * <p>{@code logging-scan} already inventories {@code Timber.}/{@code Logger.} calls, but
 * {@code log-info-leak-scan} classified sensitive logs only for {@code Log.*}/{@code System.out/err}
 * — its sink set missed the third-party frameworks. So {@code Timber.d("token=" + token)} got only
 * the coarse {@code sensitive_log} from {@code logging-scan} and never the finer
 * {@code log_token} classification here. The fix widens the shared {@code LOG_SINK_PREFIX} to also
 * match {@code Timber.<level>(} / {@code Logger.<level>(}. Same class of gap as
 * {@code Build.getSerial()} / {@code signingInfo}: a sink form the rule silently missed.
 */
class LogInfoLeakFrameworkSinkTest {

	@Test
	void timberTokenLogNowClassifies() {
		String line = "Timber.d(\"token=\" + accessToken);";
		assertTrue(LogInfoLeakScanCommand.LOG_CALL.matcher(line).find(),
				"Timber.<level>( must be recognised as a log sink");
		assertTrue(LogInfoLeakScanCommand.LOG_TOKEN.matcher(line).find(),
				"Timber.d with a token must classify as log_token, not just logging-scan's sensitive_log");
	}

	@Test
	void loggerCryptoLogNowClassifies() {
		String line = "Logger.info(\"private_key=\" + key);";
		assertTrue(LogInfoLeakScanCommand.LOG_CALL.matcher(line).find(),
				"Logger.<level>( must be recognised as a log sink");
		assertTrue(LogInfoLeakScanCommand.LOG_CRYPTO.matcher(line).find(),
				"Logger.info with a private_key must classify as log_crypto_material");
	}

	@Test
	void logDotTokenStillClassifies() {
		// Regression guard: the pre-existing Log.* form must still classify.
		String line = "Log.d(TAG, \"token=\" + token);";
		assertTrue(LogInfoLeakScanCommand.LOG_CALL.matcher(line).find());
		assertTrue(LogInfoLeakScanCommand.LOG_TOKEN.matcher(line).find());
	}

	@Test
	void systemOutTokenStillClassifies() {
		String line = "System.out.println(\"token=\" + token);";
		assertTrue(LogInfoLeakScanCommand.LOG_CALL.matcher(line).find());
		assertTrue(LogInfoLeakScanCommand.LOG_TOKEN.matcher(line).find());
	}

	@Test
	void nonLogTokenOccurrenceDoesNotClassify() {
		// A bare 'token' on a non-log line (e.g. a field assignment) must not be flagged.
		String line = "String token = response.getToken();";
		assertFalse(LogInfoLeakScanCommand.LOG_CALL.matcher(line).find(),
				"an assignment is not a log call — must not pass the sink gate");
		assertFalse(LogInfoLeakScanCommand.LOG_TOKEN.matcher(line).find(),
				"without a log sink on the line, the token mention must not classify as log_token");
	}

	@Test
	void timberWithoutSensitiveKeywordDoesNotClassifyAsToken() {
		// Timber is a log sink, but a non-sensitive Timber log must not be log_token.
		String line = "Timber.d(\"view loaded\");";
		assertTrue(LogInfoLeakScanCommand.LOG_CALL.matcher(line).find(),
				"Timber.d is still a recognised sink");
		assertFalse(LogInfoLeakScanCommand.LOG_TOKEN.matcher(line).find(),
				"a Timber log without a sensitive keyword is not log_token");
	}
}
