package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Insecure Android API usage scanner — MASVS MSTG-CODE-6.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>A catch-all for unsafe Android API patterns not covered by the more specific scanners.
 * Each pattern represents a real-world vulnerability class observed in mobile security audits.
 *
 * <p>Categories (first-match-wins per line):
 * <ul>
 *   <li>{@code component_toggle} — {@code setComponentEnabledSetting} can dynamically enable/
 *       disable components, potentially bypassing permission checks</li>
 *   <li>{@code settings_secure_read} — {@code Settings.Secure/Settings.Global} reads device
 *       identifiers (ADB_ENABLED, INSTALL_NON_MARKET_APPS, USB_MASS_STORAGE_ENABLED)</li>
 *   <li>{@code device_admin_misuse} — {@code DevicePolicyManager} used to lock/wipe the device
 *       — verify it is a legitimate MDM/parental control app</li>
 *   <li>{@code usage_stats_spy} — {@code UsageStatsManager} queries app usage history —
 *       can surveil user behavior across all apps</li>
 *   <li>{@code keyguard_dismiss} — {@code KeyguardManager.dismissKeyguard} — bypasses the
 *       lock screen</li>
 *   <li>{@code package_install} — {@code PackageInstaller} / {@code ACTION_INSTALL_PACKAGE} —
 *       the app can install other APKs without user confirmation</li>
 *   <li>{@code device_identifier} — {@code Build.SERIAL} / {@code Settings.Secure.ANDROID_ID}
 *       / {@code getDeviceId()} — persistent device fingerprinting</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, truncated}}.
 */
@Command(name = "insecure-api-scan",
		description = "Detect insecure Android API usage (MASVS MSTG-CODE-6): component toggle, Settings.Secure reads, DevicePolicyManager misuse, UsageStatsManager surveillance, keyguard dismiss, package install, device identifiers. Catch-all for patterns not covered by specific scanners")
public class InsecureApiScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes that touch potentially insecure APIs. */
	private static final Pattern API_MARKER = Pattern.compile(
			"setComponentEnabledSetting|Settings\\.Secure|Settings\\.Global|DevicePolicyManager|"
					+ "UsageStatsManager|dismissKeyguard|KeyguardManager|PackageInstaller|"
					+ "ACTION_INSTALL_PACKAGE|Build\\.SERIAL|ANDROID_ID|getDeviceId|"
					+ "getSubscriberId|getSimSerialNumber");

	private static final class Rule {
		final Pattern pattern;
		final String kind;
		final String severity;
		final String detail;
		Rule(String regex, String kind, String severity, String detail) {
			this.pattern = Pattern.compile(regex);
			this.kind = kind;
			this.severity = severity;
			this.detail = detail;
		}
	}

	private static final Rule[] RULES = {
		new Rule("setComponentEnabledSetting", "component_toggle", "medium",
				"setComponentEnabledSetting() — can dynamically enable/disable components; "
						+ "could bypass permission checks or hide malicious components from the launcher"),
		new Rule("UsageStatsManager|queryUsageStats", "usage_stats_spy", "medium",
				"UsageStatsManager — queries app usage history; can surveil user behavior "
						+ "across all installed apps; verify this is a legitimate feature"),
		new Rule("dismissKeyguard|KeyguardManager\\.isKeyguardLocked", "keyguard_dismiss", "high",
				"KeyguardManager.dismissKeyguard() — bypasses the lock screen; an app can "
						+ "dismiss the device lock without user authentication"),
		new Rule("PackageInstaller|ACTION_INSTALL_PACKAGE|Intent\\.ACTION_INSTALL_PACKAGE",
				"package_install", "high",
				"PackageInstaller / ACTION_INSTALL_PACKAGE — the app can install other APKs; "
						+ "verify it does not silently install malware"),
		new Rule("DevicePolicyManager|DeviceAdminReceiver", "device_admin_misuse", "medium",
				"DevicePolicyManager / DeviceAdminReceiver — device administration capabilities; "
						+ "can lock screen, wipe data, set password policies; verify this is a legitimate "
						+ "MDM/parental control app, not ransomware"),
		new Rule("Build\\.SERIAL|getDeviceId\\s*\\(|getSubscriberId|getSimSerialNumber|"
				+ "Settings\\.Secure\\.getString.*android_id|ANDROID_ID",
				"device_identifier", "medium",
				"Persistent device identifier (Build.SERIAL / ANDROID_ID / getDeviceId / "
						+ "getSubscriberId / getSimSerialNumber) — enables device fingerprinting; "
						+ "Google Play restricts these APIs; prefer instance IDs or advertising ID"),
		new Rule("Settings\\.Secure|Settings\\.Global", "settings_secure_read", "info",
				"Settings.Secure / Settings.Global read — accesses device settings; verify "
						+ "the app does not read sensitive settings (ADB_ENABLED, "
						+ "INSTALL_NON_MARKET_APPS) for malicious purposes"),
	};

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
		int highSeverityCount = 0;

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
			if (code == null || code.isEmpty() || !API_MARKER.matcher(code).find()) {
				continue;
			}

			// Per-line first-match-wins detection; report each kind once per class.
			java.util.TreeSet<String> reportedKinds = new java.util.TreeSet<>();

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!reportedKinds.contains(r.kind) && r.pattern.matcher(line).find()) {
						findings.add(finding(r.kind, r.severity, fullName, i + 1, r.detail));
						reportedKinds.add(r.kind);
						if ("high".equals(r.severity)) {
							highSeverityCount++;
						}
						break; // first matching rule wins per line
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String kind, String severity, String className, int line, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("className", className);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "insecure-api-scan";
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
