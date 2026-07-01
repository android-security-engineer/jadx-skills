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
 * Scans for background persistence / keep-alive primitives that malware and aggressive
 * telemetry use to stay running: periodic {@link android.app.AlarmManager} alarms
 * ({@code setRepeating / setExactAndAllowWhileIdle / setAlarmClock} — the Doze-bypassing
 * variants), {@link android.os.PowerManager} wake locks (especially {@code PARTIAL_WAKE_LOCK}
 * held without a matching release), and {@code BOOT_COMPLETED} receivers that auto-start a
 * service. Each is dual-use, but together they sketch a "runs forever, phones home on a
 * schedule" shape. MASVS MSTG-RESILIENCE / MSTG-CODE. Distinct from
 * {@code runtime-integrity-scan} (self-checks) — this is the persistence/keep-alive surface.
 *
 * <p>Returns {@code {findings, count, highSeverityCount, usesAlarmManager, usesWakeLock,
 * hasBootReceiver, partialWakeLockWithoutRelease}}.
 */
@Command(name = "alarm-wakelock-scan",
		description = "Scan for background persistence: AlarmManager repeating/Doze-bypass alarms, PARTIAL_WAKE_LOCK, BOOT_COMPLETED auto-start")
public class AlarmWakelockScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern MARKER = Pattern.compile(
			"AlarmManager|PowerManager|WakeLock|newWakeLock|BOOT_COMPLETED|setRepeating|setExact|RECEIVE_BOOT_COMPLETED");

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
			new Rule("setRepeating\\s*\\(|setInexactRepeating\\s*\\(",
					"alarm_repeating", "medium",
					"AlarmManager.setRepeating / setInexactRepeating — schedules a recurring alarm; the classic background-keep-alive / periodic-phone-home primitive"),
			new Rule("setExactAndAllowWhileIdle\\s*\\(|setExact\\s*\\(|setAlarmClock\\s*\\(",
					"alarm_doze_bypass", "high",
					"AlarmManager setExactAndAllowWhileIdle / setExact / setAlarmClock — fires precisely even in Doze; abused to defeat idle-mode battery optimisation for covert wake-ups"),
			new Rule("newWakeLock\\s*\\(.*PARTIAL_WAKE_LOCK|PARTIAL_WAKE_LOCK",
					"wakelock_partial", "medium",
					"PowerManager.newWakeLock(PARTIAL_WAKE_LOCK) — keeps the CPU running with screen off; long-held partial wake locks drain battery and keep background work alive"),
			new Rule("setExactAndAllowWhileIdle.*\\n.*\\.acquire\\s*\\(|\\.acquire\\s*\\(",
					"wakelock_acquire", "low",
					"WakeLock.acquire() — takes the lock; verify a matching release() exists or it is held indefinitely"),
			new Rule("BOOT_COMPLETED|RECEIVE_BOOT_COMPLETED",
					"boot_completed", "medium",
					"BOOT_COMPLETED / RECEIVE_BOOT_COMPLETED — app starts itself on device boot; combined with a service this is the auto-start-on-reboot persistence primitive"),
			new Rule("JobScheduler|JobInfo\\.Builder|FirebaseJobDispatcher|WorkManager",
					"background_scheduler", "low",
					"Modern background scheduler (JobScheduler/WorkManager) — the legitimate alternative to raw alarms; presence lowers the likelihood of malicious keep-alive"));

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
		boolean usesAlarmManager = false;
		boolean usesWakeLock = false;
		boolean hasBootReceiver = false;
		boolean partialWakeLockWithoutRelease = false;

		// Manifest: RECEIVE_BOOT_COMPLETED permission + BOOT_COMPLETED receiver.
		String manifest = loadManifest(decompiler);
		boolean manifestBootPermission = manifest != null
				&& manifest.contains("RECEIVE_BOOT_COMPLETED");

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
			if (code == null || code.isEmpty() || !MARKER.matcher(code).find()) {
				continue;
			}

			if (code.contains("AlarmManager")) {
				usesAlarmManager = true;
			}
			if (code.contains("WakeLock") || code.contains("newWakeLock")) {
				usesWakeLock = true;
				if (code.contains("PARTIAL_WAKE_LOCK") && !code.contains("release()")) {
					partialWakeLockWithoutRelease = true;
				}
			}
			if (code.contains("BOOT_COMPLETED")) {
				hasBootReceiver = true;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!r.pattern.matcher(line).find()) {
						continue;
					}
					findings.add(finding(fullName, i + 1, r.kind, r.severity, r.detail));
					if ("high".equals(r.severity)) {
						highSeverityCount++;
					}
					break;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("usesAlarmManager", usesAlarmManager);
		data.put("usesWakeLock", usesWakeLock);
		data.put("hasBootReceiver", hasBootReceiver || manifestBootPermission);
		data.put("hasBootPermission", manifestBootPermission);
		data.put("partialWakeLockWithoutRelease", partialWakeLockWithoutRelease);
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
		return "alarm-wakelock-scan";
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
