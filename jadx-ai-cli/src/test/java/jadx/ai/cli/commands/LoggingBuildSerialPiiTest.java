package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code Build.getSerial()} / {@code Build.SERIAL} PII-log coverage in
 * {@link LoggingScanCommand}.
 *
 * <p>{@code PII_GETTER} covered the telephony device-id getters but missed {@code Build.getSerial()}
 * — the API 26+ replacement for the deprecated {@code Build.SERIAL} field, which
 * {@code insecure-api-scan} already flags as a device identifier (added this session). Logging
 * {@code Build.getSerial()} to logcat is the same PII-leak class as logging {@code getDeviceId()}.
 * {@code Build\.getSerial} is not matched by any pre-existing {@code PII_GETTER} term.
 */
class LoggingBuildSerialPiiTest {

	private static final Pattern PII = Pattern.compile(LoggingScanCommand.PII_GETTER_REGEX);

	private static boolean piiOn(String line) {
		return PII.matcher(line).find();
	}

	@Test
	void buildGetSerialNowMatches() {
		assertTrue(piiOn("Log.d(TAG, Build.getSerial());"),
				"Build.getSerial() is the API 26+ device identifier — logging it is PII");
		assertTrue(piiOn("Log.d(TAG, android.os.Build.getSerial());"),
				"fully-qualified Build.getSerial() must match");
	}

	@Test
	void buildSerialFieldNowMatches() {
		assertTrue(piiOn("Log.d(TAG, Build.SERIAL);"),
				"the deprecated Build.SERIAL field is a persistent device identifier — logging it is PII");
	}

	@Test
	void getDeviceIdAndFriendsStillMatch() {
		assertTrue(piiOn("Log.d(TAG, telephonyManager.getDeviceId());"));
		assertTrue(piiOn("Log.d(TAG, telephonyManager.getSubscriberId());"));
		assertTrue(piiOn("Log.d(TAG, telephonyManager.getSimSerialNumber());"));
		assertTrue(piiOn("Log.d(TAG, getMacAddress());"));
	}

	@Test
	void getMeidAndIccSerialNumberNowMatch() {
		// getMeid() is the CDMA twin of getImei(); getIccSerialNumber() is a synonym of
		// getSimSerialNumber(). Both are the same hardware-identifier class and were missing.
		assertTrue(piiOn("Log.d(TAG, telephonyManager.getMeid());"),
				"logging getMeid() is PII — must match");
		assertTrue(piiOn("Log.d(TAG, telephonyManager.getIccSerialNumber());"),
				"logging getIccSerialNumber() is PII — must match");
	}

	@Test
	void androidIdGetterStillMatches() {
		assertTrue(piiOn("Log.d(TAG, getAndroidId());"));
	}

	@Test
	void unrelatedGetSerialDoesNotMatch() {
		// A getSerial() NOT on Build (e.g. BluetoothDevice) is a different API, out of PII scope here.
		// The regex anchors Build.getSerial, so a bare getSerial() must not match.
		assertFalse(piiOn("Log.d(TAG, device.getSerial());"),
				"a non-Build getSerial() is not the Build.SERIAL replacement");
	}

	@Test
	void unrelatedSerialTextDoesNotMatch() {
		assertFalse(piiOn("Log.d(TAG, \"serial number=\" + count);"),
				"the word 'serial' in a log message is not a Build.SERIAL read");
	}
}
