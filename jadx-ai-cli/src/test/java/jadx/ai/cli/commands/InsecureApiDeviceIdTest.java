package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code Build.getSerial()} coverage in {@link InsecureApiScanCommand}.
 *
 * <p>The device-identifier rule covered {@code Build.SERIAL} (the field, deprecated in API 26) but
 * missed {@code Build.getSerial()} — the API 26+ method that replaced it and is abused for device
 * fingerprinting (CWE-1039). {@code Build\.SERIAL} does not match {@code Build.getSerial()} (after
 * {@code Build.} is {@code getSerial}, not {@code SERIAL}).
 */
class InsecureApiDeviceIdTest {

	private static final Pattern DEVICE_ID = Pattern.compile(InsecureApiScanCommand.DEVICE_ID_REGEX);

	private static boolean deviceIdOn(String line) {
		return DEVICE_ID.matcher(line).find();
	}

	@Test
	void buildSerialFieldStillMatches() {
		assertTrue(deviceIdOn("String serial = Build.SERIAL;"),
				"the deprecated Build.SERIAL field must still match");
	}

	@Test
	void buildGetSerialMethodNowMatches() {
		assertTrue(deviceIdOn("String serial = Build.getSerial();"),
				"Build.getSerial() is the API 26+ replacement for Build.SERIAL — must match");
		assertTrue(deviceIdOn("String serial = android.os.Build.getSerial();"),
				"fully-qualified Build.getSerial() must match");
	}

	@Test
	void getDeviceIdAndFriendsStillMatch() {
		assertTrue(deviceIdOn("String id = telephonyManager.getDeviceId();"));
		assertTrue(deviceIdOn("String sub = telephonyManager.getSubscriberId();"));
		assertTrue(deviceIdOn("String sim = telephonyManager.getSimSerialNumber();"));
	}

	@Test
	void androidIdStillMatches() {
		assertTrue(deviceIdOn("String id = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID);"));
		assertTrue(deviceIdOn("String id = ANDROID_ID;"));
	}

	@Test
	void unrelatedGetSerialDoesNotMatch() {
		// A getSerial() NOT on Build (e.g. BluetoothDevice) is out of scope here — it's a different API.
		// The regex anchors Build.getSerial, so a bare getSerial() must not match.
		assertFalse(deviceIdOn("String s = device.getSerial();"),
				"a non-Build getSerial() is not the Build.SERIAL replacement");
	}
}
