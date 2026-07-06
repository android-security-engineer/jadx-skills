package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code setKeySize(weak)} AndroidKeyStore coverage in
 * {@link CryptographicMisuseScanCommand#WEAK_KEY_SIZE}.
 *
 * <p>{@code WEAK_KEY_SIZE} covered the legacy {@code keySize=} assignment and {@code KeyGenerator}
 * transformation strings, but missed {@code KeyGenParameterSpec.Builder.setKeySize(int)} — the API 23+
 * AndroidKeyStore standard way to set key size. Modern Android crypto code calls
 * {@code spec.setKeySize(64)}; the bare {@code keySize=} regex does not match the setter call. Same
 * class of gap as {@code Build.getSerial()} / {@code signingInfo}: a modern API form the rule missed.
 */
class CryptoMisuseSetKeySizeTest {

	private static boolean weakKeyOn(String line) {
		return CryptographicMisuseScanCommand.WEAK_KEY_SIZE.matcher(line).find();
	}

	@Test
	void setKeySizeWeakNowMatches() {
		assertTrue(weakKeyOn("spec.setKeySize(64);"),
				"setKeySize(64) is a weak AndroidKeyStore key size — must match");
		assertTrue(weakKeyOn("builder.setKeySize(1024);"),
				"setKeySize(1024) is a weak RSA key size — must match");
		assertTrue(weakKeyOn("spec.setKeySize( 56 );"),
				"setKeySize with whitespace must match");
	}

	@Test
	void setKeySizeStrongDoesNotMatch() {
		assertFalse(weakKeyOn("spec.setKeySize(256);"),
				"AES-256 is the recommended key size — must not be flagged");
		assertFalse(weakKeyOn("builder.setKeySize(2048);"),
				"RSA-2048 is the recommended minimum — must not be flagged");
		assertFalse(weakKeyOn("spec.setKeySize(4096);"),
				"RSA-4096 is strong — must not be flagged");
	}

	@Test
	void legacyKeySizeAssignmentStillMatches() {
		assertTrue(weakKeyOn("int keySize = 56;"),
				"the legacy keySize= assignment form must still match");
		assertTrue(weakKeyOn("int keySize = 112;"));
	}

	@Test
	void rsa1024StillMatches() {
		assertTrue(weakKeyOn("KeyPairGenerator.getInstance(\"RSA\").initialize(1024);"));
		assertTrue(weakKeyOn("String algo = \"RSA\"; init(1024); // RSA 1024"),
				"the RSA.*1024 form must still match");
	}

	@Test
	void desStillMatches() {
		assertTrue(weakKeyOn("KeyGenerator.getInstance(\"DES\");"));
	}

	@Test
	void unrelatedSetKeySizeDoesNotMatch() {
		// A setKeySize call with a non-weak, non-listed value must not match.
		assertFalse(weakKeyOn("spec.setKeySize(3072);"),
				"a strong setKeySize value must not be flagged");
	}
}
