package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.ManifestUtil;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Maps declared Android permissions to the dangerous APIs that exercise them, and (optionally)
 * locates the call sites of those APIs in the decompiled code. Helps an analyst see not just
 * what a permission allows, but where the app actually uses it. Native capability.
 */
@Command(name = "permission-risk-map", description = "Map declared permissions to dangerous APIs and their call sites")
public class PermissionRiskMapCommand extends AbstractCommand {

	@Option(names = { "--dangerous-only" }, description = "Only report dangerous-class permissions", defaultValue = "true")
	protected boolean dangerousOnly = true;

	@Option(names = { "--with-callsites" }, description = "Locate API call sites in code", defaultValue = "true")
	protected boolean withCallsites = true;

	@Option(names = { "--limit" }, description = "Maximum call sites per API", defaultValue = "50")
	protected int limit = 50;

	/** A dangerous permission and the API tokens that signal its use. */
	private static final class PermRisk {
		final String permission;
		final String[] apiTokens;

		PermRisk(String permission, String... apiTokens) {
			this.permission = permission;
			this.apiTokens = apiTokens;
		}
	}

	// Curated permission -> dangerous-API table (token substrings searched in decompiled code).
	private static final List<PermRisk> TABLE = List.of(
			new PermRisk("android.permission.ACCESS_FINE_LOCATION",
					"getLastKnownLocation", "requestLocationUpdates", "LocationManager", "FusedLocationProvider"),
			new PermRisk("android.permission.ACCESS_COARSE_LOCATION",
					"getLastKnownLocation", "requestLocationUpdates", "LocationManager"),
			new PermRisk("android.permission.READ_CONTACTS",
					"ContactsContract", "CommonDataKinds"),
			new PermRisk("android.permission.READ_SMS",
					"content://sms", "SmsManager", "getMessagesFromIntent"),
			new PermRisk("android.permission.SEND_SMS",
					"sendTextMessage", "sendMultipartTextMessage", "SmsManager"),
			new PermRisk("android.permission.RECORD_AUDIO",
					"MediaRecorder", "AudioRecord", "startRecording"),
			new PermRisk("android.permission.CAMERA",
					"Camera.open", "android.hardware.camera2", "CameraManager", "takePicture"),
			new PermRisk("android.permission.READ_PHONE_STATE",
					"getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber", "TelephonyManager"),
			new PermRisk("android.permission.READ_EXTERNAL_STORAGE",
					"getExternalStorageDirectory", "MediaStore", "openInputStream"),
			new PermRisk("android.permission.WRITE_EXTERNAL_STORAGE",
					"getExternalStorageDirectory", "FileOutputStream", "MediaStore"),
			new PermRisk("android.permission.READ_CALL_LOG",
					"CallLog", "content://call_log"),
			new PermRisk("android.permission.GET_ACCOUNTS",
					"AccountManager", "getAccounts"),
			new PermRisk("android.permission.SYSTEM_ALERT_WINDOW",
					"TYPE_APPLICATION_OVERLAY", "addView", "WindowManager"),
			new PermRisk("android.permission.REQUEST_INSTALL_PACKAGES",
					"ACTION_INSTALL_PACKAGE", "PackageInstaller"),
			new PermRisk("android.permission.READ_CALENDAR",
					"CalendarContract"),
			new PermRisk("android.permission.BODY_SENSORS",
					"SensorManager", "TYPE_HEART_RATE"));

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("dangerousOnly")) {
			this.dangerousOnly = Boolean.TRUE.equals(args.get("dangerousOnly"));
		}
		if (args.containsKey("withCallsites")) {
			this.withCallsites = Boolean.TRUE.equals(args.get("withCallsites"));
		}
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		String manifest = ManifestUtil.loadManifestText(decompiler);
		if (manifest == null) {
			return JsonOutput.error("ManifestNotFound", "AndroidManifest.xml not found in resources");
		}
		List<String> declared = ManifestUtil.extractPermissions(manifest);

		// Determine which dangerous permissions are declared.
		List<PermRisk> active = new ArrayList<>();
		for (PermRisk pr : TABLE) {
			if (declared.contains(pr.permission)) {
				active.add(pr);
			}
		}

		List<Map<String, Object>> dangerous = new ArrayList<>();
		for (PermRisk pr : active) {
			Map<String, Object> entry = new LinkedHashMap<>();
			entry.put("permission", pr.permission);
			entry.put("apiSignals", List.of(pr.apiTokens));
			if (withCallsites) {
				entry.put("callSites", findCallSites(decompiler, pr));
			}
			dangerous.add(entry);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("declaredPermissions", declared);
		data.put("dangerousDeclaredCount", active.size());
		data.put("dangerous", dangerous);
		if (!dangerousOnly) {
			List<String> nonDangerous = new ArrayList<>(declared);
			nonDangerous.removeIf(p -> active.stream().anyMatch(a -> a.permission.equals(p)));
			data.put("otherPermissions", nonDangerous);
		}
		return JsonOutput.ok(data);
	}

	private List<Map<String, Object>> findCallSites(JadxDecompiler decompiler, PermRisk pr) {
		List<Map<String, Object>> sites = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			if (sites.size() >= limit) {
				break;
			}
			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty()) {
				continue;
			}
			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && sites.size() < limit; i++) {
				for (String token : pr.apiTokens) {
					if (lines[i].contains(token)) {
						Map<String, Object> site = new LinkedHashMap<>();
						site.put("className", cls.getFullName());
						site.put("lineNumber", i + 1);
						site.put("api", token);
						sites.add(site);
						break;
					}
				}
			}
		}
		return sites;
	}

	@Override
	protected String getDaemonCommandName() {
		return "permission-risk-map";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("dangerousOnly", dangerousOnly);
		args.put("withCallsites", withCallsites);
		args.put("limit", limit);
		return args;
	}
}
