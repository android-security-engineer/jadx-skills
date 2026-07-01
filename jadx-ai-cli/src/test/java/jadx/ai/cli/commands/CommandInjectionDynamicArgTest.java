package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the dynamic-arg-form fix in {@link CommandInjectionScanCommand}.
 *
 * <p>Before the fix, only {@code " +} / {@code + "} concatenation set {@code concat=true}. A command
 * built with {@code String.format}, {@code StringBuilder.append}, {@code .concat}, or
 * {@code MessageFormat} and fed straight into {@code Runtime.exec(...)} /
 * {@code new ProcessBuilder(...)} is the same injection class but fell through to
 * {@code process_exec/info}. The fix treats those forms as concatenation too.
 */
class CommandInjectionDynamicArgTest {

	private static boolean concat(String line) {
		return CommandInjectionScanCommand.isCommandConcatenation(line);
	}

	@Test
	void literalPlusConcatStillFires() {
		assertTrue(concat("Runtime.getRuntime().exec(\"ls \" + input);"),
				"literal+variable concatenation must still fire");
	}

	@Test
	void stringFormatExecFires() {
		assertTrue(concat("Runtime.getRuntime().exec(String.format(\"ls %s\", input));"),
				"String.format feeding exec is dynamic concatenation — must fire high, not fall to info");
	}

	@Test
	void stringBuilderAppendExecFires() {
		assertTrue(concat("new ProcessBuilder(new StringBuilder(\"ls \").append(input).toString().split(\" \"));"),
				"StringBuilder.append feeding ProcessBuilder is dynamic concatenation — must fire");
	}

	@Test
	void concatMethodExecFires() {
		assertTrue(concat("getRuntime().exec(\"ls \".concat(input));"),
				".concat feeding exec is dynamic concatenation — must fire");
	}

	@Test
	void staticExecDoesNotFire() {
		assertFalse(concat("Runtime.getRuntime().exec(\"ls -la\");"),
				"a fully static command is not concatenation");
		assertFalse(concat("ProcessBuilder pb = new ProcessBuilder(\"ls\");"),
				"a static ProcessBuilder is not concatenation");
	}

	@Test
	void stringFormatOutsideExecDoesNotFire() {
		// String.format used for logging, not feeding an exec sink, must not be misreported.
		assertFalse(concat("Log.i(TAG, String.format(\"count=%d\", n));"),
				"String.format not feeding an exec sink is not command concatenation");
	}

	@Test
	void stringFormatInLaterExecArgumentFires() {
		// After widening EXEC_DYNAMIC_ARG's first branch from sink-immediately-followed-by to
		// sink-then-[^;]*?-followed-by, a String.format in a later exec argument is caught too:
		// exec("sh","-c",String.format(...)) — the multi-arg shell form, same injection class.
		assertTrue(concat("Runtime.getRuntime().exec(\"sh\", \"-c\", String.format(\"ls %s\", input));"),
				"a String.format in a later exec argument must fire high, not fall to info");
	}

	@Test
	void staticExecWithUnrelatedStringFormatAfterSemicolonDoesNotFire() {
		// The [^;]*? boundary blocks cross-statement FP: a static (non-concatenated) exec followed
		// by an unrelated String.format after the statement's ';' must NOT fire.
		assertFalse(concat("Runtime.getRuntime().exec(\"ls -la\"); Log.i(TAG, String.format(\"n=%d\", n));"),
				"a static exec must not fire just because an unrelated String.format sits after the ; on the same line");
	}
}
