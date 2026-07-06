package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards two real-world hardcoded-crypto shapes that {@link HardcodedCryptoScanCommand} used to miss,
 * plus the FP guards that the new decimal byte-array arm must still respect.
 *
 * <p>The scanner is per-line, so it only fires when a literal sits on the line that the regex sees.
 * These jadx-decompiled forms put the literal on a <b>source line</b> that the old arms did not
 * anchor:
 *
 * <ol>
 *   <li><b>IV variable-indirect</b> — {@code byte[] iv = "0102030405060708".getBytes();}
 *       then {@code new IvParameterSpec(iv)}. The sink line has no literal; the source-line arm of
 *       {@link HardcodedCryptoScanCommand#HARDCODED_IV} closes the gap.</li>
 *   <li><b>Symmetric-key variable-indirect</b> — {@code byte[] keyBytes = "MySecretKey123".getBytes();}
 *       then {@code new SecretKeySpec(keyBytes, "AES")}. The name-gated source-line arm of
 *       {@link HardcodedCryptoScanCommand#HARDCODED_SYMMETRIC_KEY} closes the gap without firing on
 *       generic non-key buffers.</li>
 * </ol>
 */
class HardcodedCryptoIndirectAndDecimalTest {

	private static final Pattern IV = HardcodedCryptoScanCommand.HARDCODED_IV;
	private static final Pattern KEY = HardcodedCryptoScanCommand.HARDCODED_SYMMETRIC_KEY;
	private static final Pattern KEY_BYTES = HardcodedCryptoScanCommand.HARDCODED_KEY_BYTES;

	// --- 1. decimal byte array (FP-suppression reversal — full cases in HardcodedCryptoJadxFormTest) ---
	// The decimal form is asserted in HardcodedCryptoJadxFormTest.decimalByteArrayFires; here we only
	// confirm the FP guards that the new decimal arm must still respect.

	@Test
	void sizedByteArrayDoesNotFire() {
		assertFalse(KEY_BYTES.matcher("byte[] buf = new byte[16];").find(),
				"a sized array with no literal body must NOT fire — not hardcoded material");
	}

	@Test
	void methodSignatureDoesNotFire() {
		assertFalse(KEY_BYTES.matcher("void encrypt(byte[] data, int mode) {").find(),
				"a method signature mentioning byte[] must NOT fire");
	}

	@Test
	void emptyByteArrayDoesNotFire() {
		assertFalse(KEY_BYTES.matcher("byte[] empty = new byte[]{};").find(),
				"an empty byte-array literal must NOT fire");
	}

	// --- 2. IV variable-indirect ---

	@Test
	void ivVariableIndirectSourceLineFires() {
		assertTrue(IV.matcher("byte[] iv = \"0102030405060708\".getBytes();").find(),
				"a byte[] iv assigned from a long string literal's getBytes() must fire");
	}

	@Test
	void ivVariableIndirectSinkLineDoesNotFire() {
		assertFalse(IV.matcher("cipher.init(ENCRYPT_MODE, key, new IvParameterSpec(iv));").find(),
				"the sink line new IvParameterSpec(iv) has no literal — must NOT fire on its own; "
						+ "the source line fires instead (per-class ONE finding)");
	}

	@Test
	void ivShortStringDoesNotFire() {
		assertFalse(IV.matcher("byte[] iv = \"short\".getBytes();").find(),
				"a short string below the {8,} floor must NOT fire — avoids short-string FP");
	}

	// --- 3. symmetric-key variable-indirect (name-gated) ---

	@Test
	void keyBytesVariableIndirectFires() {
		assertTrue(KEY.matcher("byte[] keyBytes = \"MySecretKey12345\".getBytes();").find(),
				"a byte[] keyBytes assigned from a long string literal must fire");
	}

	@Test
	void aesKeyVariableIndirectFires() {
		assertTrue(KEY.matcher("byte[] aesKey = \"0123456789abcdef\".getBytes();").find(),
				"a byte[] aesKey assigned from a long string literal must fire");
	}

	@Test
	void nonKeyBufferDoesNotFire() {
		assertFalse(KEY.matcher("byte[] data = \"somepayload123\".getBytes();").find(),
				"a non-key-named buffer must NOT fire the symmetric-key rule — name-gate prevents FP");
	}

	@Test
	void ivBufferDoesNotFireKeyRule() {
		assertFalse(KEY.matcher("byte[] iv = \"0102030405060708\".getBytes();").find(),
				"an IV-named buffer must NOT fire the symmetric-key rule — handled by the IV rule");
	}
}
