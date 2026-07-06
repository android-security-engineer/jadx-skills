package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the custom-padding false-positive fix in {@link UnsafeEncryptionScanCommand#CUSTOM_PADDING}.
 *
 * <p>The previous rule matched the standard JCA padding names {@code NoPadding}/{@code PKCS1Padding}/
 * {@code ISO10126Padding}/{@code X923Padding} and flagged every legitimate {@code AES/GCM/NoPadding}
 * (the recommended authenticated-encryption form) and {@code RSA/ECB/PKCS1Padding} as "custom
 * padding" — a false positive on correct crypto. Standard padding misuse is the job of
 * {@code cryptographic-misuse-scan}'s {@code rsa_without_oaep}/{@code ecb_mode} rules.
 */
class UnsafeEncryptionCustomPaddingFpTest {

	private static final Pattern PADDING = Pattern.compile(UnsafeEncryptionScanCommand.CUSTOM_PADDING.pattern());

	private static boolean paddingOn(String line) {
		return PADDING.matcher(line).find();
	}

	@Test
	void customPaddingNameStillFires() {
		assertTrue(paddingOn("int r = customPadding(data, blockLen);"),
				"a named customPadding routine must still fire");
		assertTrue(paddingOn("private byte[] myPadding(byte[] block) {"),
				"a named myPadding routine must still fire");
		assertTrue(paddingOn("paddingScheme = 2; // home-rolled"));
		assertTrue(paddingOn("void implementPadding() {"));
	}

	@Test
	void aesGcmNoPaddingDoesNotFire() {
		// AES/GCM/NoPadding is the RECOMMENDED authenticated-encryption transformation.
		assertFalse(paddingOn("Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");"),
				"AES/GCM/NoPadding is the recommended AEAD form — must NOT be flagged as custom padding");
	}

	@Test
	void rsaPkcs1PaddingDoesNotFire() {
		// RSA/ECB/PKCS1Padding is standard (if not OAEP-grade); its misuse is rsa_without_oaep's job.
		assertFalse(paddingOn("Cipher c = Cipher.getInstance(\"RSA/ECB/PKCS1Padding\");"),
				"PKCS1Padding is a standard JCA padding name — must NOT be flagged as custom padding");
	}

	@Test
	void cbcPkcs5PaddingDoesNotFire() {
		assertFalse(paddingOn("Cipher c = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");"),
				"PKCS5Padding is standard — must not be flagged");
	}

	@Test
	void iso10126AndX923DoNotFire() {
		// ISO 10126 and ANSI X9.23 are standard (if uncommon) padding schemes, not custom.
		assertFalse(paddingOn("Cipher c = Cipher.getInstance(\"AES/CBC/ISO10126Padding\");"),
				"ISO10126Padding is a standard scheme — must not be flagged as custom");
		assertFalse(paddingOn("Cipher c = Cipher.getInstance(\"AES/CBC/X923Padding\");"),
				"X923Padding is a standard scheme — must not be flagged as custom");
	}

	@Test
	void noPaddingLiteralDoesNotFire() {
		// A bare NoPadding in a non-cipher context should not trigger either.
		assertFalse(paddingOn("String mode = \"NoPadding\";"),
				"the NoPadding literal must not trigger custom_padding");
	}
}
