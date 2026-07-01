package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code Log.println} sink added to {@link LoggingScanCommand#LOG_SINK}.
 *
 * <p>{@code Log.println(int priority, String tag, String msg)} is a static direct-to-logcat write
 * that the enumerated {@code Log.(v|d|i|w|e|wtf)} set did not list, so a line like
 * {@code Log.println(Log.DEBUG, TAG, "token="+token)} was not inventoried by {@code logging-scan}
 * — even though {@code log-info-leak-scan}'s broader {@code Log\.[a-z]+} prefix already covered
 * it, leaving the two scanners asymmetric. {@code println} is a base logcat sink and belongs here.
 */
class LoggingLogPrintlnSinkTest {

	private static boolean sinkOn(String line) {
		return LoggingScanCommand.LOG_SINK.matcher(line).find();
	}

	@Test
	void logPrintlnIsSink() {
		assertTrue(sinkOn("Log.println(Log.DEBUG, TAG, \"token=\" + token);"),
				"Log.println is a direct-to-logcat sink — must be inventoried");
		assertTrue(sinkOn("Log.println(3, \"tag\", msg);"),
				"a numeric-priority Log.println must be a sink");
	}

	@Test
	void logLevelSinksStillFire() {
		assertTrue(sinkOn("Log.d(TAG, \"hello\");"), "Log.d must still be a sink (regression guard)");
		assertTrue(sinkOn("Log.e(TAG, \"err\", e);"), "Log.e must still be a sink");
		assertTrue(sinkOn("Log.wtf(TAG, \"wtf\");"), "Log.wtf must still be a sink");
	}

	@Test
	void systemOutAndFrameworksStillFire() {
		assertTrue(sinkOn("System.out.println(\"x\");"), "System.out.println must still be a sink");
		assertTrue(sinkOn("Timber.d(\"x\");"), "Timber.d must still be a sink");
		assertTrue(sinkOn("Logger.info(\"x\");"), "Logger.info must still be a sink");
	}

	@Test
	void nonLogCallDoesNotFire() {
		assertFalse(sinkOn("String tag = \"Log.d\";"),
				"a string literal mentioning Log.d is not a log call");
		assertFalse(sinkOn("int v = 1;"),
				"an unrelated statement is not a sink");
	}
}
