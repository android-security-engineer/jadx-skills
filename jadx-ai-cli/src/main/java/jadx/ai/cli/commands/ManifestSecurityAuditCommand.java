package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;

/**
 * Performs a comprehensive security audit of the AndroidManifest.xml with a
 * risk scoring system. Absorbs the manifest-analyzer and permissions-checker
 * design from {@code mobile-security-mcp} (which extracts security flags,
 * exported components, intent filters, and dangerous permissions from manifest)
 * and enriches it with a weighted scoring model. Unlike the existing
 * {@code manifest-audit} command, this produces a single composite risk score
 * and per-category findings with severity ratings.
 */
@Command(name = "manifest-security-audit", description = "Comprehensive manifest security audit with risk scoring")
public class ManifestSecurityAuditCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum findings per category", defaultValue = "50")
	protected int limit = 50;

	/** Dangerous permission set (Android dangerous permissions). */
	private static final String[] DANGEROUS_PERMISSIONS = {
		"READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_MMS", "WRITE_SMS", "RECEIVE_MMS",
		"READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
		"RECORD_AUDIO", "PROCESS_OUTGOING_CALLS", "READ_CALL_LOG", "WRITE_CALL_LOG",
		"CALL_PHONE", "ADD_VOICEMAIL", "USE_SIP",
		"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
		"CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
		"READ_PHONE_STATE", "READ_PHONE_NUMBERS",
		"USE_BIOMETRIC", "USE_FINGERPRINT",
		"BODY_SENSORS", "ACTIVITY_RECOGNITION",
		"BLUETOOTH_CONNECT", "BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE",
		"NFC", "READ_CALENDAR", "WRITE_CALENDAR",
		"PACKAGE_USAGE_STATS", "BIND_DEVICE_ADMIN", "INSTALL_PACKAGES", "DELETE_PACKAGES",
		"NEARBY_WIFI_DEVICES"
	};

	private static final Pattern PERM_PATTERN = Pattern.compile("uses-permission[^>]+android:name=\"([^\"]+)\"");
	// `<activity` not followed by `-alias`, then a word boundary — so <activity-alias> is NOT matched as
	// an activity. `activity` is a prefix of `activity-alias`, and `\b` alone still matches at the
	// `y`/`-` boundary, so the `(?!-alias)` lookahead is required. activity-alias has its own type below.
	static final Pattern ACTIVITY_PATTERN = Pattern.compile("<activity(?!-alias)\\b[^>]*android:name=\"([^\"]+)\"");
	static final Pattern ACTIVITY_ALIAS_PATTERN = Pattern.compile("<activity-alias\\b[^>]*android:name=\"([^\"]+)\"");
	private static final Pattern SERVICE_PATTERN = Pattern.compile("<service\\b[^>]*android:name=\"([^\"]+)\"");
	private static final Pattern RECEIVER_PATTERN = Pattern.compile("<receiver\\b[^>]*android:name=\"([^\"]+)\"");
	private static final Pattern PROVIDER_PATTERN = Pattern.compile("<provider\\b[^>]*android:name=\"([^\"]+)\"");
	private static final Pattern EXPORTED_TRUE = Pattern.compile("android:exported=\"true\"");
	private static final Pattern INTENT_FILTER = Pattern.compile("<intent-filter");
	private static final Pattern ACTION_NAME = Pattern.compile("<action[^>]+android:name=\"([^\"]+)\"");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		// Find AndroidManifest.xml in resources
		String manifestXml = null;
		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name != null && name.replace('\\', '/').endsWith("AndroidManifest.xml")) {
				try {
					manifestXml = res.loadContent().getText().toString();
				} catch (Exception e) {
					// Skip
				}
				break;
			}
		}

		if (manifestXml == null) {
			return JsonOutput.error("NoManifest", "AndroidManifest.xml not found in APK resources");
		}

		// ── 1. Security Flags ──
		List<Map<String, Object>> flagFindings = new ArrayList<>();
		boolean debuggable = manifestXml.contains("android:debuggable=\"true\"");
		boolean allowBackup = manifestXml.contains("android:allowBackup=\"true\"");
		boolean cleartextTraffic = manifestXml.contains("android:usesCleartextTraffic=\"true\"");
		boolean hasNetworkSecurityConfig = manifestXml.contains("android:networkSecurityConfig");
		boolean usesCleartextDefault = !hasNetworkSecurityConfig;

		if (debuggable) addFinding(flagFindings, "debuggable", "high", "App is debuggable in production — can be attached with a debugger");
		if (allowBackup) addFinding(flagFindings, "allowBackup", "medium", "App data can be extracted via adb backup without root");
		if (cleartextTraffic) addFinding(flagFindings, "usesCleartextTraffic", "high", "App allows unencrypted HTTP traffic");
		if (usesCleartextDefault && !cleartextTraffic) addFinding(flagFindings, "noNetworkSecurityConfig", "low", "No network security config — default cleartext policy applies");

		// ── 2. Permission Analysis ──
		List<String> allPerms = new ArrayList<>();
		List<String> dangerousPerms = new ArrayList<>();
		Matcher permM = PERM_PATTERN.matcher(manifestXml);
		while (permM.find()) {
			String perm = permM.group(1);
			allPerms.add(perm);
			String shortName = perm.replace("android.permission.", "");
			for (String dp : DANGEROUS_PERMISSIONS) {
				if (shortName.equals(dp)) {
					dangerousPerms.add(perm);
					break;
				}
			}
		}

		List<Map<String, Object>> permFindings = new ArrayList<>();
		for (String dp : dangerousPerms) {
			String severity = getPermSeverity(dp);
			Map<String, Object> f = new LinkedHashMap<>();
			f.put("permission", dp);
			f.put("severity", severity);
			f.put("risk", getPermRiskDescription(dp));
			permFindings.add(f);
		}

		// ── 3. Exported Components ──
		List<Map<String, Object>> exportedFindings = new ArrayList<>();
		String[] componentTypes = {"activity", "activity-alias", "service", "receiver", "provider"};
		for (String type : componentTypes) {
			Pattern compPat = getComponentPattern(type);
			Matcher cm = compPat.matcher(manifestXml);
			int lastStart = 0;
			while (cm.find()) {
				String compName = cm.group(1);
				// Check if this component block contains exported=true or has intent-filter
				int compStart = cm.start();
				// Find the end of this component element
				int compEnd = findComponentEnd(manifestXml, compStart);
				String compBlock = manifestXml.substring(compStart, compEnd);

				boolean exported = compBlock.contains("android:exported=\"true\"");
				boolean hasIntentFilter = compBlock.contains("<intent-filter");

				if (exported || (hasIntentFilter && !compBlock.contains("android:exported=\"false\""))) {
					Map<String, Object> f = new LinkedHashMap<>();
					f.put("type", type);
					f.put("name", compName);
					f.put("explicitlyExported", exported);
					f.put("hasIntentFilter", hasIntentFilter);
					f.put("severity", type.equals("provider") ? "high" : type.equals("receiver") ? "high" : "medium");
					exportedFindings.add(f);
				}
			}
		}

		// ── 4. Intent Filters ──
		List<String> intentActions = new ArrayList<>();
		Matcher actionM = ACTION_NAME.matcher(manifestXml);
		while (actionM.find() && intentActions.size() < limit) {
			intentActions.add(actionM.group(1));
		}

		// ── 5. Calculate Risk Score ──
		int score = 100; // Start at 100 (best), subtract for issues
		score -= debuggable ? 25 : 0;
		score -= allowBackup ? 10 : 0;
		score -= cleartextTraffic ? 15 : 0;
		score -= Math.min(dangerousPerms.size() * 3, 20);
		score -= Math.min(exportedFindings.size() * 5, 25);
		score = Math.max(0, score);

		String riskLevel;
		if (score >= 80) riskLevel = "low";
		else if (score >= 60) riskLevel = "medium";
		else if (score >= 40) riskLevel = "high";
		else riskLevel = "critical";

		// ── Build Result ──
		Map<String, Object> data = new LinkedHashMap<>();
		data.put("riskScore", score);
		data.put("riskLevel", riskLevel);
		data.put("securityFlags", flagFindings);
		data.put("dangerousPermissions", permFindings);
		data.put("dangerousPermissionCount", dangerousPerms.size());
		data.put("totalPermissionCount", allPerms.size());
		data.put("exportedComponents", exportedFindings);
		data.put("exportedComponentCount", exportedFindings.size());
		data.put("intentFilterActions", intentActions);
		return JsonOutput.ok(data);
	}

	private void addFinding(List<Map<String, Object>> findings, String flag, String severity, String description) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("flag", flag);
		f.put("severity", severity);
		f.put("description", description);
		findings.add(f);
	}

	private Pattern getComponentPattern(String type) {
		switch (type) {
			case "activity": return ACTIVITY_PATTERN;
			case "activity-alias": return ACTIVITY_ALIAS_PATTERN;
			case "service": return SERVICE_PATTERN;
			case "receiver": return RECEIVER_PATTERN;
			case "provider": return PROVIDER_PATTERN;
			default: return ACTIVITY_PATTERN;
		}
	}

	/**
	 * Index just past the end of the component element starting at {@code start}. A self-closing
	 * component ({@code <activity .../>}) ends at its own {@code >}; a block component
	 * ({@code <activity ...>...</activity>}) ends after its matching close tag, honouring nested
	 * children. Package-private so a test can assert the self-closing form does not overreach into the
	 * next component (which would cross-attribute exported/intent-filter flags).
	 */
	static int findComponentEnd(String xml, int start) {
		int depth = 0;
		for (int i = start; i < xml.length(); i++) {
			if (xml.charAt(i) != '<') {
				continue;
			}
			if (i + 1 < xml.length() && xml.charAt(i + 1) == '/') {
				depth--;
				if (depth <= 0) {
					int end = xml.indexOf('>', i);
					return end > 0 ? end + 1 : xml.length();
				}
				continue;
			}
			if (xml.substring(i).startsWith("<!--")) {
				continue;
			}
			int closePos = xml.indexOf('>', i);
			if (closePos < 0) {
				return xml.length();
			}
			if (xml.charAt(closePos - 1) == '/') {
				// Self-closing tag. If this is the component's opening tag (depth == 0), the component
				// ends right here — previously this `continue`d past it, absorbing following components.
				if (depth == 0) {
					return closePos + 1;
				}
				continue;
			}
			depth++;
		}
		return xml.length();
	}

	private String getPermSeverity(String perm) {
		String s = perm.replace("android.permission.", "");
		if (s.equals("READ_SMS") || s.equals("SEND_SMS") || s.equals("CALL_PHONE")
				|| s.equals("INSTALL_PACKAGES") || s.equals("BIND_DEVICE_ADMIN")) {
			return "critical";
		}
		if (s.equals("ACCESS_FINE_LOCATION") || s.equals("ACCESS_BACKGROUND_LOCATION")
				|| s.equals("CAMERA") || s.equals("RECORD_AUDIO")
				|| s.equals("READ_CONTACTS") || s.equals("READ_CALL_LOG")) {
			return "high";
		}
		return "medium";
	}

	private String getPermRiskDescription(String perm) {
		String s = perm.replace("android.permission.", "");
		switch (s) {
			case "READ_SMS": return "Can read all SMS messages — enables message interception";
			case "SEND_SMS": return "Can send SMS — potential toll fraud";
			case "CALL_PHONE": return "Can make phone calls without user interaction";
			case "CAMERA": return "Can access camera — potential covert recording";
			case "RECORD_AUDIO": return "Can record audio — potential covert surveillance";
			case "ACCESS_FINE_LOCATION": return "Precise location tracking";
			case "ACCESS_BACKGROUND_LOCATION": return "Background location tracking";
			case "READ_CONTACTS": return "Can read all contacts";
			case "READ_CALL_LOG": return "Can read call history";
			case "READ_PHONE_STATE": return "Can read device identifiers (IMEI, etc.)";
			case "INSTALL_PACKAGES": return "Can install arbitrary APKs — high risk";
			case "BIND_DEVICE_ADMIN": return "Device admin — difficult to uninstall";
			default: return "Dangerous permission grants access to sensitive data";
		}
	}

	@Override
	protected String getDaemonCommandName() {
		return "manifest-security-audit";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("limit", limit);
		return args;
	}
}
