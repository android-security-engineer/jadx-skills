package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the false-positive fix in {@link CryptographicMisuseScanCommand#MD5_SECURITY} and
 * {@link CryptographicMisuseScanCommand#SHA1_SECURITY}.
 *
 * <p>The {@code MD5.*password}/{@code MD5.*hash}/{@code MD5.*verify}/{@code MD5.*check} arms (and
 * the SHA-1 equivalents) paired the algorithm token with arbitrary same-line substrings, so a
 * comment ({@code // MD5 is broken - never hash passwords}) or a log line
 * ({@code Log.w(TAG, "MD5 verify failed")}) was flagged <b>high</b>. Now restricted to a real
 * {@code MessageDigest}/{@code Signature}/{@code SecretKeyFactory} call context.
 */
class CryptoMisuseMd5Sha1FpTest {

	private static final java.util.regex.Pattern MD5_SECURITY = CryptographicMisuseScanCommand.MD5_SECURITY;
	private static final java.util.regex.Pattern SHA1_SECURITY = CryptographicMisuseScanCommand.SHA1_SECURITY;

	// --- MD5 false positives must NOT fire ---

	@Test
	void md5CommentDoesNotFire() {
		assertFalse(MD5_SECURITY.matcher("    // MD5 is broken - never hash passwords with it").find(),
				"a comment mentioning MD5 + password must NOT fire (was a high FP)");
	}

	@Test
	void md5LogDoesNotFire() {
		assertFalse(MD5_SECURITY.matcher("    Log.w(TAG, \"MD5 verify failed for \" + name);").find(),
				"a log string mentioning MD5 + verify must NOT fire");
	}

	// --- MD5 true positives still fire ---

	@Test
	void md5GetInstanceStillFires() {
		assertTrue(MD5_SECURITY.matcher("    MessageDigest md = MessageDigest.getInstance(\"MD5\");").find(),
				"MessageDigest.getInstance(\"MD5\") must still fire");
	}

	@Test
	void md5StringThenGetInstanceStillFires() {
		assertTrue(MD5_SECURITY.matcher(
				"    String algo = \"MD5\"; MessageDigest md = MessageDigest.getInstance(algo);").find(),
				"a \"MD5\" string literal feeding MessageDigest.getInstance must still fire");
	}

	// --- SHA-1 false positives must NOT fire ---

	@Test
	void sha1CommentDoesNotFire() {
		assertFalse(SHA1_SECURITY.matcher("    // SHA-1 signature is deprecated; use SHA-256").find(),
				"a comment mentioning SHA-1 + signature must NOT fire");
	}

	// --- SHA-1 true positives still fire ---

	@Test
	void sha1MessageDigestStillFires() {
		assertTrue(SHA1_SECURITY.matcher("    MessageDigest.getInstance(\"SHA-1\");").find(),
				"MessageDigest.getInstance(\"SHA-1\") must still fire");
	}

	@Test
	void sha1SignatureStillFires() {
		assertTrue(SHA1_SECURITY.matcher("    Signature.getInstance(\"SHA1withRSA\");").find(),
				"Signature.getInstance(\"SHA1withRSA\") — SHA-1 for signatures — must still fire");
	}

	@Test
	void pbkdf2Sha1StillFires() {
		assertTrue(SHA1_SECURITY.matcher(
				"    SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA1\");").find(),
				"PBKDF2WithHmacSHA1 (SHA-1-as-PRF KDF) must still fire");
	}
}
