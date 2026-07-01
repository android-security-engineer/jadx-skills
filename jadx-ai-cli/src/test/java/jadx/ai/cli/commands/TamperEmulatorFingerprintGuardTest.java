package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code Build.FINGERPRINT} false-positive fix in {@link TamperDetectionScanCommand}.
 *
 * <p>Before the fix, the emulator rule listed a bare {@code Build.FINGERPRINT} as a marker, so any
 * legit code reading the device fingerprint (crash reporting, device fingerprinting, risk control)
 * was misreported as emulator detection. Real emulator detection compares the fingerprint/model/
 * hardware against concrete emulator values — those value strings (google_sdk, vbox86p,
 * "Android SDK built for x86", goldfish, generic_x86, …) and a {@code Build.<field>.<compare>("generic")}
 * form are the only things that should fire now.
 */
class TamperEmulatorFingerprintGuardTest {

	private static boolean fires(String line) {
		return TamperDetectionScanCommand.EMULATOR_PATTERN.matcher(line).find();
	}

	@Test
	void bareFingerprintReadDoesNotFire() {
		// The false positive being fixed: a plain field read for crash reporting / fingerprinting.
		assertFalse(fires("String fingerprint = Build.FINGERPRINT;"),
				"a bare Build.FINGERPRINT read is not emulator detection");
		assertFalse(fires("Log.i(TAG, \"fp=\" + Build.FINGERPRINT);"),
				"logging the fingerprint is not emulator detection");
	}

	@Test
	void fingerprintComparedToGenericFires() {
		// Real emulator detection compares against the "generic" value.
		assertTrue(fires("if (Build.FINGERPRINT.startsWith(\"generic\")) return true;"),
				"comparing the fingerprint to \"generic\" IS emulator detection");
		assertTrue(fires("return Build.BRAND.equals(\"generic\");"),
				"comparing the brand to \"generic\" IS emulator detection");
		assertTrue(fires("if (Build.MODEL.contains(\"google_sdk\")) return true;"));
	}

	@Test
	void concreteEmulatorValueStringsFire() {
		assertTrue(fires("return \"google_sdk\".equals(Build.MODEL);"));
		assertTrue(fires("if (Build.HARDWARE.contains(\"goldfish\")) return true;"));
		assertTrue(fires("if (Build.FINGERPRINT.contains(\"generic_x86\")) return true;"));
		assertTrue(fires("return Build.PRODUCT.equals(\"vbox86p\");"));
		assertTrue(fires("String fp = Build.FINGERPRINT; if (fp.contains(\"Android SDK built for x86\")) return true;"));
	}

	@Test
	void isEmulatorHelperStillFires() {
		assertTrue(fires("public boolean isEmulator() { return false; }"),
				"a method literally named isEmulator is still a signal");
	}

	@Test
	void nonBuildGenericUsageDoesNotFire() {
		// The word "generic" outside a Build-field comparison must not fire (avoids a new FP).
		assertFalse(fires("List<Object> generic = new ArrayList<>();"),
				"the word 'generic' in a generic-type variable is not emulator detection");
		assertFalse(fires("// generic handler for all events"),
				"'generic' in a comment is not emulator detection");
	}

	@Test
	void qemuAndGenymotionStillFire() {
		assertTrue(fires("if (Build.MODEL.contains(\"Genymotion\")) return true;"));
		assertTrue(fires("return /dev/qemu_pipe exists;"));
	}
}
