package jadx.ai.cli.commands;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import jadx.ai.cli.JadxAICLI;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the boolean-flag folding fix for {@code partialWakeLockWithoutRelease} in
 * {@link AlarmWakelockScanCommand}.
 *
 * <p>{@code PowerManager.PARTIAL_WAKE_LOCK} is a {@code static final int} (=0x1) that javac/d8 folds
 * to the integer literal {@code 1}. jadx therefore emits {@code newWakeLock(1, "MyTag").acquire()}
 * — the identifier {@code PARTIAL_WAKE_LOCK} never appears. The flag was computed via
 * {@code code.contains("PARTIAL_WAKE_LOCK")}, which is ALWAYS FALSE on real decompiled output — a
 * silent always-false flag telling the AI "no un-released partial wakelock" for EVERY app, even
 * ones that have it. Fixed by reusing {@link AlarmWakelockScanCommand#WAKELOCK_PARTIAL} (matches
 * both the identifier and the folded {@code 1} form) instead of the bare {@code code.contains}.
 *
 * <p>The fixture {@code wakelock-folded.dex} was built from real Java source
 * ({@code newWakeLock(PARTIAL_WAKE_LOCK, ...).acquire()} with NO {@code release()}) compiled via
 * javac&#8594;d8&#8594;jadx, so it exercises the exact folded form the flag must catch.
 */
class AlarmWakelockPartialFlagFoldedTest {

	private static File wakelockDex;

	@BeforeAll
	static void setup() {
		wakelockDex = new File("src/test/resources/samples/wakelock-folded.dex");
		assertTrue(wakelockDex.exists(),
				"wakelock-folded.dex fixture missing: " + wakelockDex.getAbsolutePath());
	}

	private String runCommand(String... args) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream capture = new PrintStream(baos);
		PrintStream oldOut = System.out;
		PrintStream oldErr = System.err;
		try {
			System.setOut(capture);
			System.setErr(new PrintStream(new ByteArrayOutputStream()));
			new picocli.CommandLine(new JadxAICLI()).execute(args);
		} finally {
			System.setOut(oldOut);
			System.setErr(oldErr);
		}
		return baos.toString();
	}

	@Test
	void partialWakeLockWithoutReleaseFlaggedOnFoldedForm() {
		// The fixture decompiles to `newWakeLock(1, "MyTag").acquire()` — PARTIAL_WAKE_LOCK folded
		// to `1`, and NO release() call. Before the fix this flagged partialWakeLockWithoutRelease
		// as false (the bare code.contains("PARTIAL_WAKE_LOCK") missed the folded `1`). After the fix
		// the WAKELOCK_PARTIAL pattern matches `newWakeLock(1,` and the missing release() sets the flag.
		String output = runCommand("alarm-wakelock-scan", wakelockDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "scan should succeed: " + output);
		assertTrue(output.contains("\"partialWakeLockWithoutRelease\": true"),
				"a partial wakelock acquired without release() — in the FOLDED `newWakeLock(1, ...)` form "
						+ "jadx actually emits — must set partialWakeLockWithoutRelease=true (was always-false): " + output);
		assertTrue(output.contains("\"usesWakeLock\": true"),
				"usesWakeLock must also be true: " + output);
		assertTrue(output.contains("\"truncated\""),
				"truncated flag must be present: " + output);
	}
}
