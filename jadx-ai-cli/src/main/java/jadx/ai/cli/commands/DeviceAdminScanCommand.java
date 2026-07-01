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
import jadx.api.ResourceFile;

/**
 * Scans for device-administrator capability — a privileged surface that can lock the device,
 * wipe data, reset passwords, and enforce password quality. A declared
 * {@link android.app.admin.DeviceAdminReceiver} plus an
 * {@link android.app.admin.DevicePolicyManager} wielding {@code lockNow / wipeData /
 * resetPassword / setPasswordQuality} is the MDM / abuse shape; malware historically used
 * device-admin for ransomware and persistent control. Reports the receiver subclass, the
 * manifest {@code <device-admin>} policies, and each dangerous DPM call. MASVS
 * MSTG-PLATFORM. Distinct from {@code runtime-integrity-scan} (self-checks) and
 * {@code tamper-detection-scan} (anti-analysis); this is app-as-admin capability.
 *
 * <p>Returns {@code {findings, count, highSeverityCount, hasDeviceAdmin, hasDpmAbuse,
 * adminReceivers, manifestPolicies}}.
 */
@Command(name = "device-admin-scan",
		description = "Scan for DeviceAdminReceiver + DevicePolicyManager dangerous APIs (lockNow/wipeData/resetPassword) and manifest <device-admin>")
public class DeviceAdminScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern DPM_MARKER = Pattern.compile(
			"DeviceAdminReceiver|DevicePolicyManager|DEVICE_ADMIN_ENABLED|android\\.app\\.admin");

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

	private static final List<Rule> RULES = List.of(
			new Rule("extends\\s+DeviceAdminReceiver",
					"device_admin_receiver", "medium",
					"Subclass of DeviceAdminReceiver — the entry point granted device-admin privileges once the user accepts the system prompt; required to wield DevicePolicyManager"),
			new Rule("wipeData\\s*\\(",
					"dpm_wipe_data", "high",
					"DevicePolicyManager.wipeData() — factory-resets the device (or only app data with FLAG); ransomware primitive"),
			new Rule("resetPassword\\s*\\(",
					"dpm_reset_password", "high",
					"DevicePolicyManager.resetPassword() — sets a new lockscreen password without knowing the current one; lockout primitive"),
			new Rule("lockNow\\s*\\(",
					"dpm_lock_now", "medium",
					"DevicePolicyManager.lockNow() — immediately locks the device screen; denial-of-service / ransomware"),
			new Rule("setPasswordQuality\\s*\\(|setPasswordMinimumLength\\s*\\(|setPasswordMinimumLetters\\s*\\(",
					"dpm_password_policy", "low",
					"Enforces password quality/length via DevicePolicyManager — legitimate MDM, but also a lockout-enabling capability"),
			new Rule("setMaximumTimeToLock\\s*\\(|setMaximumFailedPasswordsForWipe\\s*\\(",
					"dpm_wipe_on_fail", "high",
					"DevicePolicyManager setMaximumTimeToLock / setMaximumFailedPasswordsForWipe — auto-lock or auto-wipe on failed unlocks"),
			new Rule("setCameraDisabled\\s*\\(|setKeyguardDisabled\\s*\\(|setUserRestriction\\s*\\(",
					"dpm_restrict", "medium",
					"DevicePolicyManager disables camera / keyguard or sets user restrictions — hostageware capability"));

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
		boolean hasDeviceAdmin = false;
		boolean hasDpmAbuse = false;
		List<String> adminReceivers = new ArrayList<>();

		// 1. Manifest <device-admin> declaration + policies
		List<String> manifestPolicies = new ArrayList<>();
		String manifest = loadManifest(decompiler);
		if (manifest != null) {
			if (manifest.contains("BIND_DEVICE_ADMIN")) {
				hasDeviceAdmin = true;
				manifestPolicies.add("BIND_DEVICE_ADMIN");
			}
			java.util.regex.Matcher usesP = Pattern.compile(
					"<uses-policy\\s+android:name\\s*=\\s*\"([^\"]+)\"").matcher(manifest);
			while (usesP.find()) {
				manifestPolicies.add(usesP.group(1));
			}
		}

		// 2. Code scan
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
			if (code == null || code.isEmpty() || !DPM_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			boolean reportedReceiver = false;
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!r.pattern.matcher(line).find()) {
						continue;
					}
					findings.add(finding(fullName, i + 1, r.kind, r.severity, r.detail));
					if ("high".equals(r.severity)) {
						highSeverityCount++;
						hasDpmAbuse = true;
					}
					if ("device_admin_receiver".equals(r.kind) && !reportedReceiver) {
						reportedReceiver = true;
						adminReceivers.add(fullName);
						hasDeviceAdmin = true;
					}
					break;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("hasDeviceAdmin", hasDeviceAdmin);
		data.put("hasDpmAbuse", hasDpmAbuse);
		data.put("adminReceivers", adminReceivers);
		data.put("manifestPolicies", manifestPolicies);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String cls, int line, String kind, String severity, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("className", cls);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	private static String loadManifest(JadxDecompiler decompiler) {
		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name != null && name.replace('\\', '/').endsWith("AndroidManifest.xml")) {
				try {
					return res.loadContent().getText().toString();
				} catch (Exception e) {
					return null;
				}
			}
		}
		return null;
	}

	@Override
	protected String getDaemonCommandName() {
		return "device-admin-scan";
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
