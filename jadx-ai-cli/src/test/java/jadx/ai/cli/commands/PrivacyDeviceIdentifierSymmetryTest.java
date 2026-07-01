package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code device_identifier} rule's coverage of the ICC-serial and Widevine-MediaDrm
 * identifiers in {@link PrivacyScanCommand#DEVICE_IDENTIFIER_REGEX}.
 *
 * <p>The privacy inventory must catch every persistent hardware identifier — the same
 * device-identifier class that {@code insecure-api-scan} and {@code logging-scan} flag. But the old
 * rule listed only IMEI/MEID/IMSI/SIM-serial/Build.SERIAL/phone-number, silently missing two
 * same-class identifiers that the other two scanners already caught (batch 18): the SIM
 * {@code getIccSerialNumber()} (a synonym of {@code getSimSerialNumber()}) and the MediaDrm
 * {@code getWidevineDeviceId()} / {@code getPropertyMediaDrm("deviceUniqueId")} (a fingerprinting
 * fallback to evade the ANDROID_ID/Serial Play restrictions). A privacy review would under-disclose
 * collection of these.
 */
class PrivacyDeviceIdentifierSymmetryTest {

	private static final Pattern RULE = Pattern.compile(PrivacyScanCommand.DEVICE_IDENTIFIER_REGEX);

	private static boolean fires(String line) {
		return RULE.matcher(line).find();
	}

	@Test
	void coreIdentifiersStillFire() {
		assertTrue(fires("String imei = tm.getImei();"), "getImei must fire (regression guard)");
		assertTrue(fires("String id = tm.getDeviceId();"), "getDeviceId must fire (regression guard)");
		assertTrue(fires("String serial = Build.SERIAL;"), "Build.SERIAL must fire (regression guard)");
		assertTrue(fires("String meid = tm.getMeid();"), "getMeid must fire (regression guard)");
	}

	@Test
	void iccSerialNumberFires() {
		assertTrue(fires("String icc = tm.getIccSerialNumber();"),
				"getIccSerialNumber is a SIM serial synonym — must fire as device_identifier");
	}

	@Test
	void widevineDeviceIdFires() {
		assertTrue(fires("String wid = mediaDrm.getWidevineDeviceId();"),
				"MediaDrm.getWidevineDeviceId is a persistent fingerprinting ID — must fire");
	}

	@Test
	void propertyMediaDrmFires() {
		assertTrue(fires("String duid = mediaDrm.getPropertyMediaDrm(\"deviceUniqueId\");"),
				"getPropertyMediaDrm reading the device-unique ID is fingerprinting — must fire");
	}

	@Test
	void nonIdentifierDoesNotFire() {
		assertFalse(fires("String pkg = getPackageName();"),
				"getPackageName is not a hardware identifier — must not fire");
		assertFalse(fires("int api = Build.VERSION.SDK_INT;"),
				"Build.VERSION.SDK_INT is not a device identifier — must not fire");
	}
}
