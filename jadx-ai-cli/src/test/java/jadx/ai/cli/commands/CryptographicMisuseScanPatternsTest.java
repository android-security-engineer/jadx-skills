package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the high-value crypto-misuse detection regexes that close real MASVS gaps: bare-algorithm
 * ECB default, RSA without OAEP, and hardcoded/static IVs. These are the patterns most commonly
 * missed by "/ECB"-only scanners, so they are unit-tested directly against representative code
 * snippets (positive and negative) rather than via a decompiled fixture.
 */
class CryptographicMisuseScanPatternsTest {

	private static boolean m(java.util.regex.Pattern p, String s) {
		return p.matcher(s).find();
	}

	@Test
	void implicitEcbFlagsBareBlockCipherNames() {
		assertTrue(m(CryptographicMisuseScanCommand.IMPLICIT_ECB, "Cipher.getInstance(\"AES\")"));
		assertTrue(m(CryptographicMisuseScanCommand.IMPLICIT_ECB, "Cipher.getInstance(\"DES\", provider)"));
		assertTrue(m(CryptographicMisuseScanCommand.IMPLICIT_ECB, "Cipher.getInstance( \"Blowfish\" )"));
	}

	@Test
	void implicitEcbIgnoresFullTransformationStrings() {
		assertFalse(m(CryptographicMisuseScanCommand.IMPLICIT_ECB, "Cipher.getInstance(\"AES/GCM/NoPadding\")"));
		assertFalse(m(CryptographicMisuseScanCommand.IMPLICIT_ECB, "Cipher.getInstance(\"AES/CBC/PKCS5Padding\")"));
	}

	@Test
	void rsaWithoutOaepFlagsBareAndPkcs1() {
		assertTrue(m(CryptographicMisuseScanCommand.RSA_NO_OAEP, "Cipher.getInstance(\"RSA\")"));
		assertTrue(m(CryptographicMisuseScanCommand.RSA_NO_OAEP, "Cipher.getInstance(\"RSA/None/NoPadding\")"));
		assertTrue(m(CryptographicMisuseScanCommand.RSA_NO_OAEP, "Cipher.getInstance(\"RSA/ECB/PKCS1Padding\")"));
	}

	@Test
	void rsaWithoutOaepAllowsOaepPadding() {
		assertFalse(m(CryptographicMisuseScanCommand.RSA_NO_OAEP,
				"Cipher.getInstance(\"RSA/ECB/OAEPwithSHA-256andMGF1Padding\")"));
	}

	@Test
	void staticIvFlagsLiteralIvs() {
		assertTrue(m(CryptographicMisuseScanCommand.STATIC_IV, "new IvParameterSpec(new byte[]{0, 1, 2, 3})"));
		assertTrue(m(CryptographicMisuseScanCommand.STATIC_IV, "new IvParameterSpec(\"1234567890123456\".getBytes())"));
	}

	@Test
	void staticIvIgnoresRandomIvVariable() {
		assertFalse(m(CryptographicMisuseScanCommand.STATIC_IV, "new IvParameterSpec(randomIv)"));
	}
}
