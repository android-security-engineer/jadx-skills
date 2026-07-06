package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the false-positive fix to the source-line arm of
 * {@link HardcodedCryptoScanCommand#HARDCODED_IV}.
 *
 * <p>The bare {@code byte[]\s*\w*\s*=\s*"[^"]{8,}".getBytes} arm accepted ANY variable name, so a
 * non-IV buffer in a crypto class (a digest magic "SIGMAGIC9", a signature prefix) — which jadx
 * keeps as {@code byte[] bytes = "SIGMAGIC9".getBytes()} when the variable is used more than once —
 * was flagged {@code hardcoded_iv} <b>high</b>. Now name-gated to IV-ish names
 * ({@code iv}/{@code nonce}/{@code initVector}/{@code initializationVector}), mirroring
 * {@link HardcodedCryptoScanCommand#HARDCODED_SYMMETRIC_KEY}. The inline {@code IvParameterSpec("...")}
 * arm still catches the un-named case. Verified against real javac&#8594;d8&#8594;jadx output.
 */
class HardcodedCryptoIvSourceLineFpTest {

	private static final java.util.regex.Pattern HARDCODED_IV = HardcodedCryptoScanCommand.HARDCODED_IV;

	@Test
	void nonIvBufferDoesNotFire() {
		assertFalse(HARDCODED_IV.matcher("        byte[] bytes = \"SIGMAGIC9\".getBytes();").find(),
				"a non-IV buffer (digest magic) in a crypto class must NOT fire hardcoded_iv (was a high FP)");
	}

	@Test
	void fileHeaderBufferDoesNotFire() {
		assertFalse(HARDCODED_IV.matcher("        byte[] header = \"PNGHEADER\".getBytes();").find(),
				"a file-header buffer must NOT fire");
	}

	@Test
	void ivSourceLineStillFires() {
		assertTrue(HARDCODED_IV.matcher("        byte[] iv = \"0102030405060708\".getBytes();").find(),
				"a named IV source line must still fire");
	}

	@Test
	void nonceSourceLineStillFires() {
		assertTrue(HARDCODED_IV.matcher("        byte[] nonce = \"abc12345\".getBytes();").find(),
				"a named nonce source line must still fire");
	}

	@Test
	void initVectorSourceLineStillFires() {
		assertTrue(HARDCODED_IV.matcher("        byte[] initVector = \"12345678\".getBytes();").find(),
				"a named initVector source line must still fire");
	}

	@Test
	void inlineIvParameterSpecStillFires() {
		assertTrue(HARDCODED_IV.matcher(
				"        new IvParameterSpec(\"0102030405060708\".getBytes());").find(),
				"the inline IvParameterSpec(\"...\") arm must still fire (un-named case)");
	}

	@Test
	void ivAssignmentStillFires() {
		assertTrue(HARDCODED_IV.matcher("        IV = \"0102030405060708\";").find(),
				"the `IV = \"...\"` arm must still fire");
	}
}
