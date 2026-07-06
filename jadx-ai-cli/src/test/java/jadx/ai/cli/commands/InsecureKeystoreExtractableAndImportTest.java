package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the two promised-but-never-emitted KeyStore findings in {@link InsecureKeystoreScanCommand}.
 *
 * <p>The class javadoc lists {@code key_extractable} and {@code key_not_bound_to_device} as findings,
 * and the matching regexes were even defined ({@code SET_UNLOCKED_DEVICE_FALSE},
 * {@code KEY_IMPORT_NO_PROTECTION}) — but neither was wired into {@code execute()}, so both were
 * silent false-negatives. Fixed: {@code SET_UNLOCKED_DEVICE_FALSE} fires {@code key_extractable}
 * per-line; {@code KEY_IMPORT_NO_PROTECTION} was split into {@code KEY_IMPORT} (sink) ∧
 * {@code KEY_PROTECTION_GUARD} (absence = signal) as a class-scope AND for
 * {@code key_not_bound_to_device}, mirroring {@link DataResidueScanCommand#contentProviderResidueSignal}.
 */
class InsecureKeystoreExtractableAndImportTest {

	// ---- key_extractable (setUnlockedDeviceRequired(false)) ----

	@Test
	void setUnlockedDeviceFalseFiresExtractable() {
		assertTrue(InsecureKeystoreScanCommand.SET_UNLOCKED_DEVICE_FALSE
						.matcher("builder.setUnlockedDeviceRequired(false);").find(),
				"setUnlockedDeviceRequired(false) must match the extractable signal");
	}

	@Test
	void setUnlockedDeviceTrueDoesNotFire() {
		assertFalse(InsecureKeystoreScanCommand.SET_UNLOCKED_DEVICE_FALSE
						.matcher("builder.setUnlockedDeviceRequired(true);").find(),
				"setUnlockedDeviceRequired(true) is the secure form — must not match");
	}

	// ---- key_not_bound_to_device (class-scope KEY_IMPORT ∧ ¬KEY_PROTECTION_GUARD) ----

	/** Mirrors execute()'s class-scope decision for key_not_bound_to_device. */
	private static boolean notBoundToDevice(String code) {
		return InsecureKeystoreScanCommand.KEY_IMPORT.matcher(code).find()
				&& !InsecureKeystoreScanCommand.KEY_PROTECTION_GUARD.matcher(code).find();
	}

	@Test
	void setEntryWithoutProtectionFires() {
		// A bare key import — no KeyProtection.Builder anywhere in the class.
		String code = "PrivateKey key = loadKey();\n"
				+ "ks.setEntry(\"mykey\", new KeyStore.PrivateKeyEntry(key, chain), null);";
		assertTrue(notBoundToDevice(code),
				"a setEntry with a null protection param must fire key_not_bound_to_device");
	}

	@Test
	void setEntryWithKeyProtectionDoesNotFire() {
		// The same import guarded by KeyProtection.Builder — bound to secure hardware.
		String code = "KeyProtection.Builder kp = new KeyProtection.Builder()\n"
				+ "    .setBoundToSpecificSecureHardware(true);\n"
				+ "ks.setEntry(\"mykey\", entry, kp.build());";
		assertFalse(notBoundToDevice(code),
				"a setEntry wrapped in KeyProtection.Builder is bound to secure hardware — no finding");
	}

	@Test
	void noSetEntryDoesNotFire() {
		// A class that generates a key (KeyGenParameterSpec) rather than importing one is not an import.
		String code = "KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(\"k\", PURPOSE_SIGN).build();\n"
				+ "KeyGenerator kg = KeyGenerator.getInstance(\"AES\");";
		assertFalse(notBoundToDevice(code),
				"without a setEntry there is no import to be unbound");
	}

	@Test
	void setBoundToSpecificSecureHardwareGuards() {
		// The setBoundToSpecificSecureHardware call alone is enough to suppress the finding.
		String code = "ks.setEntry(\"k\", entry, prot);\n"
				+ "boolean bound = prot.setBoundToSpecificSecureHardware(true);";
		assertFalse(notBoundToDevice(code),
				"setBoundToSpecificSecureHardware presence means the import is bound — no finding");
	}
}
