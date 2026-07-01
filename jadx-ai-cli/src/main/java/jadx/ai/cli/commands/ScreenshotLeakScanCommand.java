package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Screenshot/recent-apps leak scanner — MASVS MSTG-STORAGE-9/PLATFORM-4.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects activities that display sensitive content without
 * FLAG_SECURE (allows screenshots and recent-apps preview leaks),
 * activities that set FLAG_SECURE but clear it conditionally, and
 * sensitive views not cleared in onStop/onDestroy.
 *
 * <p>Distinct from {@code screen-capture-scan} (screen capture/recording
 * API detection — MediaProjection, screenshot API) — this scanner
 * focuses on <b>FLAG_SECURE posture and recent-apps preview leakage</b>.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code flag_secure_missing} — Activity with sensitive content markers
 *       (password/banking/payment) but no FLAG_SECURE — screenshots and
 *       recent-apps previews leak sensitive data</li>
 *   <li>{@code flag_secure_conditional} — FLAG_SECURE set only conditionally
 *       (if/when) — may be disabled in certain states</li>
 *   <li>{@code flag_secure_cleared} — FLAG_SECURE cleared after being set —
 *       window becomes capturable again</li>
 *   <li>{@code sensitive_view_not_cleared} — Sensitive view (password/credit
 *       card) not cleared in onStop/onDestroy — data persists in recent-apps
 *       preview</li>
 *   <li>{@code flag_secure_set} — FLAG_SECURE properly set — positive indicator</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasFlagSecure, hasMissingFlagSecure, truncated}}.
 */
@Command(name = "screenshot-leak-scan",
		description = "Detect screenshot/recent-apps leaks (MASVS MSTG-STORAGE-9/PLATFORM-4): missing FLAG_SECURE on sensitive activities, conditional FLAG_SECURE, sensitive views not cleared. Distinct from screen-capture-scan (capture API detection)")
public class ScreenshotLeakScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan Activity classes with window/content markers. */
	private static final Pattern ACTIVITY_MARKER = Pattern.compile(
			"Activity|FLAG_SECURE|setFlags|addFlags|getWindow|"
					+ "password|Password|login|Login|banking|payment|"
					+ "credit|card|pin|PIN|onCreate|setContentView");

	/** Sensitive content markers. */
	private static final Pattern SENSITIVE_CONTENT = Pattern.compile(
			"password|Password|passwd|login|Login|signin|signIn|"
					+ "banking|payment|Payment|credit|Credit|card_number|"
					+ "pin_entry|PinEntry|otp|OTP|auth|Auth|credential|"
					+ "ssn|social_security|account_balance");

	private static final Pattern FLAG_SECURE_SET = Pattern.compile(
			"FLAG_SECURE|flag_secure|WindowManager\\.LayoutParams\\.FLAG_SECURE");
	private static final Pattern FLAG_SECURE_CLEARED = Pattern.compile(
			"setFlags\\s*\\(.*0\\s*\\)|clearFlags\\s*\\(.*FLAG_SECURE|"
					+ "FLAG_SECURE.*false|flagSecure.*=.*false");
	private static final Pattern FLAG_SECURE_CONDITIONAL = Pattern.compile(
			"if\\s*\\(.*FLAG_SECURE|if\\s*\\(.*flagSecure|"
					+ "\\?.*FLAG_SECURE|FLAG_SECURE.*\\?.*:");
	private static final Pattern SENSITIVE_VIEW = Pattern.compile(
			"EditText.*password|TextInputLayout.*password|"
					+ "passwordInput|cardNumberInput|pinInput|"
					+ "setInputType.*TYPE_TEXT_VARIATION_PASSWORD|"
					+ "setInputType.*TYPE_NUMBER_VARIATION_PASSWORD|"
					+ "android:password\\s*=\\s*\"true\"");
	private static final Pattern ON_STOP_DESTROY = Pattern.compile(
			"onStop\\s*\\(|onDestroy\\s*\\(|onPause\\s*\\(");

	private static final class Rule {
		final Pattern pattern;
		final String kind;
		final String severity;
		final String detail;
		Rule(Pattern pattern, String kind, String severity, String detail) {
			this.pattern = pattern;
			this.kind = kind;
			this.severity = severity;
			this.detail = detail;
		}
	}

	private static final Rule[] RULES = {
		new Rule(FLAG_SECURE_CLEARED, "flag_secure_cleared", "high",
				"FLAG_SECURE cleared after being set — window becomes capturable "
						+ "again; keep FLAG_SECURE for the entire activity lifecycle"),
		new Rule(FLAG_SECURE_CONDITIONAL, "flag_secure_conditional", "medium",
				"FLAG_SECURE set conditionally — may be disabled in certain states; "
						+ "always set FLAG_SECURE for activities with sensitive content"),
		new Rule(FLAG_SECURE_SET, "flag_secure_set", "info",
				"FLAG_SECURE properly set — positive indicator; prevents screenshots "
						+ "and recent-apps preview leaks"),
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
		boolean hasFlagSecure = false;
		boolean hasMissingFlagSecure = false;

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
			if (code == null || code.isEmpty() || !ACTIVITY_MARKER.matcher(code).find()) {
				continue;
			}

			// Class-level checks
			boolean classHasSensitiveContent = SENSITIVE_CONTENT.matcher(code).find();
			boolean classHasFlagSecure = FLAG_SECURE_SET.matcher(code).find();
			boolean classHasOnStopDestroy = ON_STOP_DESTROY.matcher(code).find();
			boolean classHasSensitiveView = SENSITIVE_VIEW.matcher(code).find();

			if (classHasFlagSecure) {
				hasFlagSecure = true;
			}

			// Sensitive activity without FLAG_SECURE
			if (classHasSensitiveContent && !classHasFlagSecure) {
				findings.add(finding("flag_secure_missing", "high", fullName, 0,
						"Activity with sensitive content (password/banking/payment) without "
								+ "FLAG_SECURE — screenshots and recent-apps previews leak "
								+ "sensitive data; add getWindow().setFlags(FLAG_SECURE, FLAG_SECURE)"));
				hasMissingFlagSecure = true;
				highSeverityCount++;
				continue; // already reported for this class
			}

			// Sensitive view not cleared in onStop/onDestroy
			if (classHasSensitiveView && !classHasOnStopDestroy) {
				findings.add(finding("sensitive_view_not_cleared", "medium", fullName, 0,
						"Sensitive view (password/credit card input) not cleared in "
								+ "onStop/onDestroy — data persists in recent-apps preview; "
								+ "clear sensitive fields in lifecycle methods"));
			}

			if (findings.size() >= limit) {
				break;
			}

			// Per-line rule detection (first-match-wins, ONE/class per kind)
			TreeSet<String> reportedKinds = new TreeSet<>();
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
						break;
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("hasFlagSecure", hasFlagSecure);
		data.put("hasMissingFlagSecure", hasMissingFlagSecure);
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
		return "screenshot-leak-scan";
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
