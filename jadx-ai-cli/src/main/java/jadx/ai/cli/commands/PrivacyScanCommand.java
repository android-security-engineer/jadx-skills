package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Builds a personal-data collection inventory — MASVS-PRIVACY-1 / PRIVACY-2. Native: reads jadx's
 * parsed model, no external tool.
 *
 * <p>Distinct from {@code permission-risk-map}, which starts from the declared {@code <uses-permission>}
 * set and maps each to its risk APIs. This scanner starts from the <em>code</em> and catalogs what
 * personal data the app actually touches, grouped by data category — a data-flow inventory for a
 * privacy review / data-safety disclosure. Its real value is the data that needs <b>no dangerous
 * permission</b> and so never appears in a permission map but is squarely privacy-sensitive and
 * abused for cross-app tracking: {@code ANDROID_ID}, the advertising ID, the installed-apps list,
 * and motion sensors used for device fingerprinting. Findings are an inventory (no severity —
 * collection is a fact to disclose, not inherently a vuln), like {@code tamper-detection-scan}.
 * Categories: {@code device_identifier}, {@code advertising_id}, {@code location}, {@code contacts},
 * {@code accounts}, {@code installed_apps}, {@code camera_microphone}, {@code sensors},
 * {@code biometric_data}, {@code calendar_call_log}.
 *
 * Returns {@code {findings:[{category,className,lineNumber,detail}], count, categories{cat->count},
 * present{cat->bool}, truncated}}.
 */
@Command(name = "privacy-scan",
		description = "Inventory personal-data collection (MASVS-PRIVACY): device identifiers, advertising ID, location, contacts, accounts, installed-apps enumeration, camera/mic, sensors. Catches non-permissioned fingerprinting (ANDROID_ID, ad-id, app list) that permission-risk-map misses")
public class PrivacyScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "400")
	protected int limit = 400;

	private static final class Rule {
		final Pattern pattern;
		final String category;
		final String detail;

		Rule(String regex, String category, String detail) {
			this.pattern = Pattern.compile(regex);
			this.category = category;
			this.detail = detail;
		}
	}

	/** Any line matching the marker anchors the scan to a privacy-relevant class. */
	private static final Pattern PRIVACY_MARKER = Pattern.compile(
			"getDeviceId|getImei|getSubscriberId|getSimSerialNumber|Build\\.SERIAL|getSerial|"
					+ "ANDROID_ID|getAdvertisingId|AdvertisingIdClient|getLastKnownLocation|requestLocationUpdates|"
					+ "FusedLocation|ContactsContract|content://contacts|AccountManager|getAccounts|"
					+ "getInstalledPackages|getInstalledApplications|queryIntentActivities|MediaRecorder|"
					+ "AudioRecord|android\\.hardware\\.camera|SensorManager|CalendarContract|CallLog");

	/** First matching rule wins per line. Ordered most-specific first. */
	private static final List<Rule> RULES = List.of(
			new Rule("getDeviceId\\s*\\(|getImei\\s*\\(|getSubscriberId\\s*\\(|getSimSerialNumber\\s*\\(|getMeid\\s*\\(|Build\\.SERIAL|getSerial\\s*\\(|getLine1Number\\s*\\(",
					"device_identifier",
					"Reads a hardware/SIM identifier (IMEI / MEID / IMSI / SIM serial / Build.SERIAL / phone number) — a persistent cross-reset tracking ID"),
			new Rule("Settings\\.Secure\\.ANDROID_ID|\"android_id\"|getString\\s*\\([^)]*ANDROID_ID",
					"device_identifier",
					"Reads ANDROID_ID — a per-app-signing-key device ID used for tracking; no permission required"),
			new Rule("getAdvertisingId|AdvertisingIdClient|getId\\s*\\(\\s*\\)\\s*;?\\s*//\\s*ad|AdInfo",
					"advertising_id",
					"Reads the advertising ID — cross-app ad-tracking identifier; collection must be disclosed and is user-resettable"),
			new Rule("getLastKnownLocation\\s*\\(|requestLocationUpdates\\s*\\(|FusedLocationProvider|getLatitude\\s*\\(|getLongitude\\s*\\(|LocationManager",
					"location",
					"Collects device location (LocationManager / FusedLocation / getLatitude/Longitude)"),
			new Rule("ContactsContract|content://contacts|com\\.android\\.contacts",
					"contacts",
					"Reads the contacts database (ContactsContract / content://contacts)"),
			new Rule("AccountManager|getAccounts\\s*\\(|getAccountsByType\\s*\\(",
					"accounts",
					"Enumerates on-device accounts (AccountManager.getAccounts) — reveals the user's email/identity"),
			new Rule("getInstalledPackages\\s*\\(|getInstalledApplications\\s*\\(|queryIntentActivities\\s*\\(|getInstalledModules\\s*\\(",
					"installed_apps",
					"Enumerates installed apps (getInstalledPackages / queryIntentActivities) — a fingerprinting / profiling signal; Play policy treats the app list as personal data"),
			new Rule("MediaRecorder|AudioRecord|android\\.hardware\\.camera|Camera2|takePicture\\s*\\(|startRecording\\s*\\(",
					"camera_microphone",
					"Accesses camera or microphone (MediaRecorder / AudioRecord / Camera) — capture of audio/video"),
			new Rule("CalendarContract|content://com\\.android\\.calendar|CallLog|content://call_log",
					"calendar_call_log",
					"Reads calendar events or the call log (CalendarContract / CallLog)"),
			new Rule("SensorManager|getDefaultSensor\\s*\\(|TYPE_ACCELEROMETER|TYPE_GYROSCOPE|registerListener\\s*\\(",
					"sensors",
					"Reads motion sensors (accelerometer / gyroscope) — usable for device fingerprinting and behavioural tracking; no permission required"));

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();
		Map<String, Integer> categories = new TreeMap<>();

		for (JavaClass cls : decompiler.getClasses()) {
			if (findings.size() >= limit) {
				break;
			}
			String fullName = cls.getFullName();
			if (packageFilter != null && !fullName.startsWith(packageFilter)) {
				continue;
			}
			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty() || !PRIVACY_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!r.pattern.matcher(line).find()) {
						continue;
					}
					findings.add(finding(fullName, i + 1, r.category, r.detail));
					categories.merge(r.category, 1, Integer::sum);
					break; // one finding per line — first (most-specific) rule wins
				}
			}
		}

		Map<String, Boolean> present = new TreeMap<>();
		for (String cat : categories.keySet()) {
			present.put(cat, true);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("categories", categories);
		data.put("present", present);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String cls, int line, String category, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("category", category);
		f.put("className", cls);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "privacy-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
