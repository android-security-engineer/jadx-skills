package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the device-identifier coverage in {@link InsecureApiScanCommand}.
 *
 * <p>The device-identifier rule covered {@code Build.SERIAL} (the field, deprecated in API 26) but
 * missed {@code Build.getSerial()} — the API 26+ method that replaced it and is abused for device
 * fingerprinting (CWE-1039). {@code Build\.SERIAL} does not match {@code Build.getSerial()} (after
 * {@code Build.} is {@code getSerial}, not {@code SERIAL}). Extended to cover {@code getMeid()} /
 * {@code getIccSerialNumber()} (same hardware-identifier class) and MediaDrm Widevine device IDs
 * (a fingerprinting fallback used to evade the ANDROID_ID/Serial restrictions).
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
	void getMeidAndIccSerialNumberNowMatch() {
		// getMeid() is the CDMA twin of getImei(); getIccSerialNumber() is a synonym of
		// getSimSerialNumber(). Both are the same hardware-identifier class and were missing.
		assertTrue(deviceIdOn("String meid = telephonyManager.getMeid();"),
				"getMeid() is a persistent device identifier — must match");
		assertTrue(deviceIdOn("String iccid = telephonyManager.getIccSerialNumber();"),
				"getIccSerialNumber() is the SIM ICCID — must match");
	}

	@Test
	void mediaDrmWidevineDeviceIdNowMatches() {
		// MediaDrm Widevine device-unique IDs are a well-known fingerprinting fallback used to evade
		// the ANDROID_ID/Build.SERIAL restrictions.
		assertTrue(deviceIdOn("String id = mediaDrm.getPropertyMediaDrm(\"deviceUniqueId\");"),
				"MediaDrm getPropertyMediaDrm is a fingerprinting fallback — must match");
		assertTrue(deviceIdOn("byte[] id = mediaDrm.getWidevineDeviceId();"),
				"getWidevineDeviceId is a fingerprinting fallback — must match");
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
