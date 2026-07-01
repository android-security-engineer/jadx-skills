package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Guards {@link CryptoScanCommand#classifyCipher} against the two subtle mistakes a naive
 * mode-string scanner makes: flagging "RSA/ECB/..." as insecure ECB (the "ECB" there is a JCA
 * naming artifact for single-block RSA, not the block-chaining weakness), and conversely NOT
 * warning on RSA's PKCS#1 v1.5 padding / bare "RSA" default. Symmetric ECB detection (explicit and
 * implicit-default) must still fire.
 */
class CryptoTransformationTest {

	private static String kindFor(String transformation) {
		List<Map<String, Object>> findings = new ArrayList<>();
		new CryptoScanCommand().classifyCipher(transformation, "C", 1, findings);
		assertEquals(1, findings.size(), "exactly one finding for: " + transformation);
		return String.valueOf(findings.get(0).get("kind"));
	}

	private static String severityFor(String transformation) {
		List<Map<String, Object>> findings = new ArrayList<>();
		new CryptoScanCommand().classifyCipher(transformation, "C", 1, findings);
		return String.valueOf(findings.get(0).get("severity"));
	}

	@Test
	void rsaEcbPkcs1IsNotFlaggedAsEcbMode() {
		// The false positive being fixed: "ECB" in an RSA transformation is nominal, not a weakness.
		assertEquals("rsa_weak_padding", kindFor("RSA/ECB/PKCS1Padding"));
		assertEquals("medium", severityFor("RSA/ECB/PKCS1Padding"));
	}

	@Test
	void bareRsaWarnsAboutDefaultPkcs1Padding() {
		assertEquals("rsa_weak_padding", kindFor("RSA"));
	}

	@Test
	void rsaOaepIsClean() {
		assertEquals("cipher", kindFor("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));
		assertEquals("info", severityFor("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"));
	}

	@Test
	void symmetricEcbStillFlagged() {
		assertEquals("ecb_mode", kindFor("AES/ECB/PKCS5Padding"));
		assertEquals("high", severityFor("AES/ECB/PKCS5Padding"));
	}

	@Test
	void bareAesIsImplicitEcb() {
		assertEquals("implicit_ecb", kindFor("AES"));
		assertEquals("high", severityFor("AES"));
	}

	@Test
	void weakCipherWinsOverModeParsing() {
		assertEquals("weak_cipher", kindFor("DES/CBC/PKCS5Padding"));
	}

	@Test
	void strongAesGcmIsInfo() {
		assertEquals("cipher", kindFor("AES/GCM/NoPadding"));
		assertEquals("info", severityFor("AES/GCM/NoPadding"));
	}
}
