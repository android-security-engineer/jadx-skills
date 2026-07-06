package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the gate-vs-rule symmetry fix in {@link HardcodedCryptoScanCommand#CRYPTO_MARKER}.
 *
 * <p>The gate lacked the field-name anchors {@code KEY_BYTES}/{@code keyBytes}/{@code SALT}/{@code salt}/
 * {@code SEED}/{@code seed}. A constant-holder class
 * ({@code static final byte[] KEY_BYTES = "...".getBytes()}) with no other crypto token (no
 * {@code SecretKeySpec}/{@code Cipher}/{@code AES}/hex literal) was skipped at the gate →
 * {@code hardcoded_key_bytes}/{@code hardcoded_salt} never fired. Verified against real
 * javac&#8594;d8&#8594;jadx output.
 */
class HardcodedCryptoGateFieldNameTest {

	private static final java.util.regex.Pattern CRYPTO_MARKER = HardcodedCryptoScanCommand.CRYPTO_MARKER;

	@Test
	void keyBytesFieldMatchesGate() {
		assertTrue(CRYPTO_MARKER.matcher("static final byte[] KEY_BYTES = \"dGhp\".getBytes();").find(),
				"a KEY_BYTES constant-holder class with no other crypto token must match the gate (was skipped → FN)");
	}

	@Test
	void keyBytesCamelCaseMatchesGate() {
		assertTrue(CRYPTO_MARKER.matcher("byte[] keyBytes = \"secret\".getBytes();").find(),
				"a keyBytes field must match the gate");
	}

	@Test
	void saltFieldMatchesGate() {
		assertTrue(CRYPTO_MARKER.matcher("static final String SALT = \"fixedSaltValue1234\";").find(),
				"a SALT constant-holder must match the gate");
	}

	@Test
	void seedFieldMatchesGate() {
		assertTrue(CRYPTO_MARKER.matcher("byte[] seed = new byte[]{1,2,3};").find(),
				"a seed field must match the gate");
	}

	@Test
	void secretKeySpecStillMatchesGate() {
		assertTrue(CRYPTO_MARKER.matcher("new SecretKeySpec(key, \"AES\");").find(),
				"a SecretKeySpec reference must still match the gate");
	}
}
