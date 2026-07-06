package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code signingInfo} / {@code getSigningInfo()} coverage in
 * {@link RuntimeIntegrityScanCommand#SIGNATURE_VERIFY}.
 *
 * <p>The signature-verify rule covered {@code packageInfo.signatures} — the pre-API-28
 * {@code Signature[]} field — but missed {@code signingInfo} / {@code getSigningInfo()}, the
 * API 28+ replacement. Modern signature-verification code reads
 * {@code packageInfo.signingInfo} (a {@code SigningInfo} object) or calls
 * {@code getSigningInfo()}; {@code packageInfo\.signatures} does not match {@code signingInfo}.
 * Same class of gap as {@code Build.getSerial()} (see {@link InsecureApiDeviceIdTest}).
 */
class RuntimeIntegritySigningInfoTest {

	private static final Pattern SIGNATURE = RuntimeIntegrityScanCommand.SIGNATURE_VERIFY;

	private static boolean verifyOn(String line) {
		return SIGNATURE.matcher(line).find();
	}

	@Test
	void packageInfoSignaturesStillMatches() {
		assertTrue(verifyOn("Signature[] sigs = packageInfo.signatures;"),
				"the pre-API-28 packageInfo.signatures field must still match");
	}

	@Test
	void getSignaturesStillMatches() {
		assertTrue(verifyOn("Signature[] sigs = pm.getSignatures(pkg, GET_SIGNATURES);"),
				"PackageManager.getSignatures() must still match");
	}

	@Test
	void signingInfoFieldNowMatches() {
		assertTrue(verifyOn("SigningInfo info = packageInfo.signingInfo;"),
				"packageInfo.signingInfo is the API 28+ replacement — must match");
		assertTrue(verifyOn("SigningInfo info = pkgInfo.signingInfo;"),
				"a non-packageInfo-named variable's signingInfo field must match too");
	}

	@Test
	void getSigningInfoMethodNowMatches() {
		assertTrue(verifyOn("SigningInfo info = packageInfo.getSigningInfo();"),
				"getSigningInfo() is the API 28+ accessor — must match");
	}

	@Test
	void getSigningCertificatesAlsoMatches() {
		assertTrue(verifyOn("byte[][] certs = packageInfo.signingInfo.getApkContentsSigners();"),
				"a signingInfo-driven certificate read must match via the signingInfo term");
	}

	@Test
	void unrelatedSigningInfoTextDoesNotMatch() {
		// A bare identifier fragment inside an unrelated token must not fire.
		assertFalse(verifyOn("String note = \"verifySigningInfoHelper\";"),
				"signingInfo as a substring of an unrelated identifier is not a signature-verify signal");
	}
}
