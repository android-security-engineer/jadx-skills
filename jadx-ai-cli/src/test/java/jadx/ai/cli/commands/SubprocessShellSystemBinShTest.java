package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the Android-shell-path arm added to {@link SubprocessScanCommand#SHELL_EXECUTION}.
 *
 * <p>Android's shell lives at {@code /system/bin/sh}, and developers (especially root/permission
 * tooling) frequently write the absolute path: {@code new ProcessBuilder("/system/bin/sh","-c",cmd)}.
 * The old rule anchored on {@code "/bin/sh"} (quote then /bin/sh), so the {@code /system/bin/sh}
 * literal — where {@code /bin/sh} is preceded by {@code m}, not a quote — did not match, and the
 * shell-injection finding was silently dropped. {@code SU_COMMAND} already knew about
 * {@code /system/bin/su}; {@code SHELL_EXECUTION} lacked the parallel {@code /system/bin/sh}.
 */
class SubprocessShellSystemBinShTest {

	private static boolean fires(String line) {
		return SubprocessScanCommand.SHELL_EXECUTION.matcher(line).find();
	}

	@Test
	void systemBinShAbsolutePathFires() {
		assertTrue(fires("new ProcessBuilder(\"/system/bin/sh\", \"-c\", cmd);"),
				"the Android /system/bin/sh absolute path must fire shell_execution");
		assertTrue(fires("new ProcessBuilder(\"/system/bin/bash\", \"-c\", cmd);"),
				"/system/bin/bash must fire shell_execution");
	}

	@Test
	void binShStillFires() {
		assertTrue(fires("new ProcessBuilder(\"/bin/sh\", \"-c\", cmd);"),
				"the /bin/sh form must still fire (regression guard)");
	}

	@Test
	void shDashCArgListFires() {
		assertTrue(fires("new ProcessBuilder(\"sh\", \"-c\", cmd);"),
				"the \"sh\",\"-c\" arg-list form must still fire (regression guard)");
	}

	@Test
	void shDashCInlineFires() {
		assertTrue(fires("Runtime.getRuntime().exec(\"sh -c \" + cmd);"),
				"the inline sh -c form must still fire");
	}

	@Test
	void nonShellPathDoesNotFire() {
		assertFalse(fires("String path = \"/data/data/com.x/files/sh\";"),
				"an unrelated path mentioning 'sh' is not shell execution");
		assertFalse(fires("String log = \"push\";"),
				"an unrelated string is not shell execution");
	}
}
