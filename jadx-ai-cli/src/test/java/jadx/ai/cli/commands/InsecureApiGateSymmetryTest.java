package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code API_MARKER} gate / RULES-set symmetry in {@link InsecureApiScanCommand}.
 *
 * <p>execute() skips any class that does not match {@code API_MARKER} — so every rule's anchor must
 * also appear in the gate, or a class exercising only that rule is skipped and the finding is
 * silently dropped. This regressed for {@code getImei}: it was in {@code DEVICE_ID_REGEX} (the rule)
 * but absent from the gate, so a pure {@code tm.getImei()} class — the single most common device-
 * identifier call — was never scanned. {@code queryUsageStats} and {@code DeviceAdminReceiver} had
 * the same gate-vs-rule asymmetry.
 */
class InsecureApiGateSymmetryTest {

	/** Mirrors execute()'s class-level gate. */
	private static boolean gated(String code) {
		return InsecureApiScanCommand.API_MARKER.matcher(code).find();
	}

	@Test
	void getImeiClassPassesGate() {
		// A class whose only insecure-API touch is getImei() must pass the gate, else the
		// device_identifier finding is silently dropped.
		assertTrue(gated("String imei = tm.getImei();"),
				"getImei must be in the API_MARKER gate — a pure getImei class must not be skipped");
	}

	@Test
	void queryUsageStatsClassPassesGate() {
		assertTrue(gated("List<UsageStats> stats = usm.queryUsageStats(INTERVAL_DAILY, 0, now);"),
				"queryUsageStats must be in the gate — a usage-stats query must not be skipped");
	}

	@Test
	void deviceAdminReceiverClassPassesGate() {
		assertTrue(gated("public class MyAdmin extends DeviceAdminReceiver { }"),
				"DeviceAdminReceiver must be in the gate — a receiver subclass must not be skipped");
	}

	@Test
	void getMeidClassPassesGate() {
		assertTrue(gated("String meid = tm.getMeid();"),
				"getMeid must remain gated (regression guard)");
	}

	@Test
	void getIccSerialNumberClassPassesGate() {
		assertTrue(gated("String icc = tm.getIccSerialNumber();"),
				"getIccSerialNumber must remain gated (regression guard)");
	}

	@Test
	void widevineClassPassesGate() {
		assertTrue(gated("String wid = mediaDrm.getWidevineDeviceId();"),
				"getWidevineDeviceId must remain gated (regression guard)");
	}
}
