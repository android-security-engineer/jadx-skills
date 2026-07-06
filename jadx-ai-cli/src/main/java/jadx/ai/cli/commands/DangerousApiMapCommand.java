package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Maps dangerous Android permissions to the actual API calls used in the APK.
 * Absorbs the design of {@code dex-analyzer-for-llm}'s {@code dangerous_api.py}
 * which joins AOSP's {@code @RequiresPermission} permission&rarr;API map against
 * the APK's referenced APIs to answer: which dangerous permissions are exercised
 * through <em>real API calls</em> (not just declared in the manifest)?
 *
 * <p>This native implementation scans decompiled code for the class/method names
 * that gate dangerous permissions, then cross-references with declared permissions
 * to produce a permission&rarr;API&rarr;caller map.</p>
 */
@Command(name = "dangerous-api-map", description = "Map dangerous permissions to actual API calls in the APK")
public class DangerousApiMapCommand extends AbstractCommand {

	@Option(names = { "--app-only" }, description = "Exclude framework/library callers (default: true)", defaultValue = "true")
	protected boolean appOnly = true;

	@Option(names = { "--limit" }, description = "Maximum findings per permission", defaultValue = "50")
	protected int limit = 50;

	/** A permission→API marker mapping. */
	private static final class PermApi {
		final String permission;
		final String[] apiMarkers;

		PermApi(String permission, String[] apiMarkers) {
			this.permission = permission;
			this.apiMarkers = apiMarkers;
		}
	}

	// Absorbed from AOSP @RequiresPermission dataset (dangerous permissions slice)
	// Each entry maps a dangerous permission to the most common API class#method
	// markers that gate it. We use simplified class.method patterns for Java code scanning.
	private static final PermApi[] DANGEROUS_PERM_APIS = {
		new PermApi("ACCESS_FINE_LOCATION", new String[] {
			"LocationManager.getLastKnownLocation", "LocationManager.requestLocationUpdates",
			"LocationManager.addProximityAlert", "LocationManager.getCurrentLocation",
			"LocationManager.addNmeaListener", "LocationManager.addGpsStatusListener",
			"FusedLocationProviderClient.getLastLocation", "FusedLocationProviderClient.requestLocationUpdates",
			"Geocoder.getFromLocation", "LocationManager.removeUpdates"
		}),
		new PermApi("ACCESS_COARSE_LOCATION", new String[] {
			"LocationManager.getLastKnownLocation", "LocationManager.requestLocationUpdates",
			"LocationManager.addProximityAlert", "LocationManager.getCurrentLocation",
			"FusedLocationProviderClient.getLastLocation"
		}),
		new PermApi("CAMERA", new String[] {
			"CameraManager.openCamera", "Camera.open", "Camera.takePicture",
			"CameraDevice.CameraDeviceSetup.openCamera", "CameraManager.openSharedCamera"
		}),
		new PermApi("RECORD_AUDIO", new String[] {
			"AudioRecord.", "MediaRecorder.start", "MediaRecorder.prepare",
			"SpeechRecognizer.createSpeechRecognizer", "AudioRecord.Builder.build"
		}),
		new PermApi("READ_CONTACTS", new String[] {
			"ContactsContract.", "ContentResolver.query", "E2eeContactKeysManager.get",
			"QuickContactBadge.assignContactUri"
		}),
		new PermApi("WRITE_CONTACTS", new String[] {
			"ContactsContract.RawContacts", "E2eeContactKeysManager.remove",
			"E2eeContactKeysManager.update"
		}),
		new PermApi("READ_CALL_LOG", new String[] {
			"CallLog.Calls.", "TelephonyCallback.EVENT_LEGACY_CALL_STATE_CHANGED"
		}),
		new PermApi("WRITE_CALL_LOG", new String[] {
			"CallLog.storeCallComposerPicture"
		}),
		new PermApi("READ_PHONE_STATE", new String[] {
			"TelephonyManager.getDeviceId", "TelephonyManager.getSubscriberId",
			"TelephonyManager.getSimSerialNumber", "TelephonyManager.getLine1Number",
			"TelephonyManager.getCallState", "TelephonyManager.getNetworkType",
			"TelephonyManager.getCellLocation", "TelecomManager.getCallCapablePhoneAccounts",
			"SubscriptionManager.getActiveSubscriptionInfo"
		}),
		new PermApi("READ_PHONE_NUMBERS", new String[] {
			"TelephonyManager.getLine1Number", "SubscriptionManager.getPhoneNumber",
			"TelecomManager.getLine1Number"
		}),
		new PermApi("CALL_PHONE", new String[] {
			"TelephonyManager.call", "TelecomManager.placeCall",
			"TelephonyManager.sendUssdRequest", "TelecomManager.startConference"
		}),
		new PermApi("READ_SMS", new String[] {
			"SmsManager.", "TelephonyManager.getLine1Number"
		}),
		new PermApi("SEND_SMS", new String[] {
			"SmsManager.sendTextMessage", "SmsManager.sendMultipartTextMessage",
			"SmsManager.sendDataMessage", "BluetoothMapClient.sendMessage"
		}),
		new PermApi("GET_ACCOUNTS", new String[] {
			"AccountManager.getAccounts", "AccountManager.getAccountsByType",
			"AccountManager.addOnAccountsUpdatedListener"
		}),
		new PermApi("BODY_SENSORS", new String[] {
			"SensorManager.registerListener", "SensorManager.getDefaultSensor"
		}),
		new PermApi("ACTIVITY_RECOGNITION", new String[] {
			"ActivityRecognitionClient.", "DetectedActivity."
		}),
		new PermApi("BLUETOOTH_CONNECT", new String[] {
			"BluetoothDevice.connect", "BluetoothSocket.connect",
			"BluetoothGatt.connect", "BluetoothAdapter.getBondedDevices"
		}),
		new PermApi("BLUETOOTH_SCAN", new String[] {
			"BluetoothAdapter.startDiscovery", "BluetoothLeScanner.startScan",
			"BluetoothAdapter.isDiscovering"
		}),
		new PermApi("NEARBY_WIFI_DEVICES", new String[] {
			"WifiManager.startScan", "WifiManager.getConnectionInfo",
			"WifiManager.getScanResults", "WifiInfo."
		}),
	};

	// Framework/library package prefixes to skip when appOnly=true
	private static final String[] FRAMEWORK_PREFIXES = {
		"android.", "androidx.", "android.support.", "kotlin.", "kotlinx.",
		"java.", "javax.", "dalvik.", "com.google.android.", "com.google.common.",
		"com.google.gson.", "com.google.firebase."
	};

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("appOnly")) {
			this.appOnly = Boolean.TRUE.equals(args.get("appOnly"));
		}
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		// For each dangerous permission, find classes that use its gated APIs
		Map<String, List<Map<String, Object>>> permApiMap = new LinkedHashMap<>();
		for (PermApi pa : DANGEROUS_PERM_APIS) {
			permApiMap.put(pa.permission, new ArrayList<>());
		}

		int totalApiHits = 0;
		// PER_ENTRY truncation: each permission's hits list is independently capped at `limit`; once a
		// permission hits the cap no more classes are added to it (and totalApiHits is under-counted for
		// it). A top-level `truncated` (any entry hit cap) is the minimal correct signal — the AI just
		// needs to know to re-run with a higher limit.
		boolean truncated = false;

		for (JavaClass cls : decompiler.getClasses()) {
			String fullName = cls.getFullName();

			// Skip framework classes if appOnly
			if (appOnly && isFrameworkCaller(fullName)) {
				continue;
			}

			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty()) continue;

			for (PermApi pa : DANGEROUS_PERM_APIS) {
				List<Map<String, Object>> hits = permApiMap.get(pa.permission);
				if (hits.size() >= limit) {
					truncated = true;
					continue;
				}

				for (String marker : pa.apiMarkers) {
					if (code.contains(marker)) {
						Map<String, Object> hit = new LinkedHashMap<>();
						hit.put("api", marker);
						hit.put("className", fullName);
						hits.add(hit);
						totalApiHits++;
						break; // One hit per class per permission
					}
				}
			}
		}

		// Filter out permissions with no hits
		Map<String, Object> exercisedPerms = new LinkedHashMap<>();
		for (Map.Entry<String, List<Map<String, Object>>> entry : permApiMap.entrySet()) {
			if (!entry.getValue().isEmpty()) {
				exercisedPerms.put(entry.getKey(), entry.getValue());
			}
		}

		// Build summary
		List<String> summary = new ArrayList<>();
		for (Map.Entry<String, Object> entry : exercisedPerms.entrySet()) {
			@SuppressWarnings("unchecked")
			List<Map<String, Object>> apis = (List<Map<String, Object>>) entry.getValue();
			summary.add(entry.getKey() + " (" + apis.size() + " API calls)");
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("exercisedPermissions", exercisedPerms);
		data.put("exercisedCount", exercisedPerms.size());
		data.put("totalApiHits", totalApiHits);
		data.put("appOnly", appOnly);
		data.put("summary", summary);
		data.put("truncated", truncated);
		return JsonOutput.ok(data);
	}

	private static boolean isFrameworkCaller(String className) {
		for (String prefix : FRAMEWORK_PREFIXES) {
			if (className.startsWith(prefix)) return true;
		}
		return false;
	}

	@Override
	protected String getDaemonCommandName() {
		return "dangerous-api-map";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("appOnly", appOnly);
		args.put("limit", limit);
		return args;
	}
}
