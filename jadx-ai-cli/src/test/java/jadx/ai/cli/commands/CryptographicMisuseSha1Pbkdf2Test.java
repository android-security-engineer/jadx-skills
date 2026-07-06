package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the PBKDF2-SHA1-PRF arm of {@link CryptographicMisuseScanCommand#SHA1_SECURITY}.
 *
 * <p>{@code SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")} derives a key with SHA-1 as the
 * pseudorandom function — a SHA-1-for-security use that the old rule missed entirely: it matched
 * only {@code MessageDigest.getInstance("SHA-1"/"SHA1")}, so a password-based KDF built on SHA-1
 * passed every scanner silently. Neither {@code crypto-scan}'s {@code MessageDigest}/{@code Mac}
 * detection nor the bare-MessageDigest arm here covered {@code SecretKeyFactory}.
 */
class CryptographicMisuseSha1Pbkdf2Test {

	private static final Pattern RULE = Pattern.compile(CryptographicMisuseScanCommand.SHA1_SECURITY.pattern());

	private static boolean fires(String line) {
		return RULE.matcher(line).find();
	}

	@Test
	void pbkdf2WithHmacSha1FactoryFires() {
		assertTrue(fires("SecretKeyFactory factory = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA1\");"),
				"PBKDF2 with SHA-1 PRF is SHA-1-for-security — must fire");
	}

	@Test
	void pbkdf2WithHmacSha1LiteralFires() {
		// The algo may be assigned to a variable first; the literal still names SHA-1 as the PRF.
		assertTrue(fires("String algo = \"PBKDF2WithHmacSHA1\";"),
				"the PBKDF2WithHmacSHA1 literal names SHA-1 as the KDF PRF — must fire");
	}

	@Test
	void messageDigestSha1StillFires() {
		assertTrue(fires("MessageDigest md = MessageDigest.getInstance(\"SHA-1\");"),
				"the MessageDigest SHA-1 form must still fire (regression guard)");
		assertTrue(fires("MessageDigest.getInstance(\"SHA1\");"),
				"the SHA1 (no dash) form must still fire (regression guard)");
	}

	@Test
	void pbkdf2WithHmacSha256DoesNotFire() {
		assertFalse(fires("SecretKeyFactory factory = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\");"),
				"PBKDF2WithHmacSHA256 uses SHA-256 as the PRF — must NOT fire");
	}

	@Test
	void sha256DigestDoesNotFire() {
		assertFalse(fires("MessageDigest md = MessageDigest.getInstance(\"SHA-256\");"),
				"SHA-256 is not SHA-1 — must not fire");
	}
}
