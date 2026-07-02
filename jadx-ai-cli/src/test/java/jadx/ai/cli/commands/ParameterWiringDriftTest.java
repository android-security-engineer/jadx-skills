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
 * Guards the MCP/CLI parameter-wiring fixes (10th audit dimension: silent parameter drops).
 *
 * <p>Three transports feed each command's options (picocli @Option / McpToolDefinitions optArg /
 * applyArgs-or-dispatch {@code args.get}), hand-matched with NO automatic kebab↔camel conversion.
 * A drift between the MCP-declared optArg name and the {@code args.get} key is a SILENT DROP: the
 * MCP client sends the option, the command ignores it, the client thinks it took effect.
 *
 * <p>This test exercises the wired-through fixes end-to-end via the CLI (which shares the same
 * dispatch path for the affected options):
 * <ul>
 *   <li>{@code list --limit} — McpToolDefinitions declared {@code limit} but
 *       {@code CommandDispatch.list()} never read it (silent drop); now wired through ListCommand's
 *       new {@code --limit} + cap() helper.</li>
 * </ul>
 */
class ParameterWiringDriftTest {

	private static File testApk;

	@BeforeAll
	static void setup() {
		testApk = new File("../jadx-cli/src/test/resources/samples/small.apk");
		assertTrue(testApk.exists(), "Test APK fixture missing: " + testApk.getAbsolutePath());
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
	void listLimitCapsClassCount() {
		// small.apk has >1 class (HelloWorld + possibly others). --limit 1 must cap the classes list
		// to a single entry. Before the fix `list` had no limit support at all (MCP declared limit but
		// it was silently dropped); now ListCommand.cap() applies it.
		String unlimited = runCommand("list", "-t", "classes", testApk.getAbsolutePath());
		String limited = runCommand("list", "-t", "classes", "--limit", "1", testApk.getAbsolutePath());
		assertNotNull(unlimited);
		assertNotNull(limited);
		assertTrue(limited.contains("\"success\": true"), "limited list should succeed: " + limited);
		// Count "fullName" occurrences — the capped run must have strictly fewer than the unlimited run.
		int unlimitedCount = countOccurrences(unlimited, "\"fullName\"");
		int limitedCount = countOccurrences(limited, "\"fullName\"");
		assertTrue(limitedCount >= 1, "limited list should still return at least one class: " + limited);
		assertTrue(limitedCount <= 1,
				"--limit 1 must cap the class list to at most 1 entry, got " + limitedCount + ": " + limited);
		assertTrue(unlimitedCount > limitedCount,
				"unlimited list (" + unlimitedCount + ") must return more than the limited list ("
						+ limitedCount + ") — proves the cap actually fires");
	}

	private static int countOccurrences(String haystack, String needle) {
		int count = 0;
		int idx = 0;
		while ((idx = haystack.indexOf(needle, idx)) != -1) {
			count++;
			idx += needle.length();
		}
		return count;
	}
}
