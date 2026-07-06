package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the array-index self-XOR coverage in {@link UnsafeEncryptionScanCommand#XOR_ENCRYPTION}.
 *
 * <p>{@code XOR_ENCRYPTION} matched the literal-key ({@code ^ 0x..}), named-key ({@code ^ key}) and
 * byte-cast ({@code (byte)(a ^ b)}) forms but missed {@code arr[i] ^= key[j]} — the most common
 * decompiled shape of an XOR stream-cipher loop. The {@code byte.*\^.*byte} term requires two
 * literal "byte" tokens, so {@code out[i] = (byte)(in[i] ^ key[i])} (one cast) and
 * {@code bytes[i] ^= key[j]} (no "byte" token at all) were silent false-negatives.
 */
class UnsafeEncryptionXorLoopTest {

	private static final Pattern XOR = Pattern.compile(UnsafeEncryptionScanCommand.XOR_ENCRYPTION.pattern());

	private static boolean xorOn(String line) {
		return XOR.matcher(line).find();
	}

	@Test
	void arrayIndexSelfXorFires() {
		assertTrue(xorOn("out[i] ^= key[j];"),
				"arr[i] ^= key[j] is the canonical XOR stream-cipher loop body — must match");
		assertTrue(xorOn("bytes[i] ^= key[i % key.length];"),
				"a modulo-indexed self-XOR is an XOR cipher — must match");
	}

	@Test
	void byteCastXorLoopFires() {
		// The single-cast form (one "byte" token) — missed by the byte.*\^.*byte two-token term.
		assertTrue(xorOn("out[i] = (byte) (in[i] ^ key[i]);"),
				"a single byte-cast XOR loop body must match");
	}

	@Test
	void literalKeyXorStillFires() {
		assertTrue(xorOn("byte b = (byte) (data ^ 0x5A);"),
				"the literal-key XOR form must still match");
		assertTrue(xorOn("int x = value ^ 0xFF;"));
	}

	@Test
	void namedKeyXorStillFires() {
		assertTrue(xorOn("byte enc = (byte) (plain ^ key);"),
				"the named-key XOR form must still match");
	}

	@Test
	void xorCipherNameStillFires() {
		assertTrue(xorOn("public byte[] xorEncrypt(byte[] data, byte key) {"),
				"a method named xorEncrypt must match");
	}

	@Test
	void nonXorBitwiseDoesNotFire() {
		// A plain bitwise-and (masking) is not XOR encryption.
		assertFalse(xorOn("int mask = flags & 0x0F;"),
				"a bitwise-AND mask is not XOR encryption");
	}

	@Test
	void nonXorAssignmentDoesNotFire() {
		// A plain array assignment without ^= is not XOR.
		assertFalse(xorOn("out[i] = in[i] + key[i];"),
				"an additive assignment is not XOR encryption");
	}
}
