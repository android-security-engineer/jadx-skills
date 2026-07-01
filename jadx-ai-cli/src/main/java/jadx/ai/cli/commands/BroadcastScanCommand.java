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
 * Broadcast security scanner — MASVS MSTG-PLATFORM.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects insecure broadcast patterns: sticky broadcast data leaks,
 * implicit broadcast interception, ordered broadcast hijacking,
 * missing LocalBroadcastManager, and sensitive data in broadcasts.
 * Distinct from {@code intent-scan} (generic intent misuse) and
 * {@code intent-redirection-scan} (intent redirection attacks) —
 * this scanner focuses on <b>broadcast-specific security patterns</b>.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code sticky_broadcast} — sendStickyBroadcast / sendStickyOrderedBroadcast —
 *       data persists and is readable by any app; deprecated in API 21</li>
 *   <li>{@code implicit_broadcast_send} — sendBroadcast without explicit component —
 *       any receiver can intercept; use explicit broadcast or LocalBroadcastManager</li>
 *   <li>{@code ordered_broadcast_hijack} — sendOrderedBroadcast — receivers with
 *       higher priority can intercept and modify data; verify priority ordering</li>
 *   <li>{@code broadcast_sensitive_data} — sendBroadcast with password/token/key —
 *       sensitive data broadcast to all matching receivers</li>
 *   <li>{@code dynamic_receiver} — registerReceiver with dynamic BroadcastReceiver —
 *       remains active until unregistered; may leak if not unregistered in onPause</li>
 *   <li>{@code local_broadcast} — LocalBroadcastManager usage — positive indicator;
 *       broadcasts stay within the app</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasStickyBroadcast, hasLocalBroadcast, truncated}}.
 */
@Command(name = "broadcast-scan",
		description = "Detect broadcast security issues (MASVS MSTG-PLATFORM): sticky broadcasts, implicit broadcast interception, ordered broadcast hijacking, sensitive data in broadcasts, dynamic receiver leaks. Distinct from intent-scan (generic intent) and intent-redirection-scan (redirection attacks)")
public class BroadcastScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with broadcast markers. */
	private static final Pattern BROADCAST_MARKER = Pattern.compile(
			"sendBroadcast|sendStickyBroadcast|sendOrderedBroadcast|"
					+ "BroadcastReceiver|registerReceiver|LocalBroadcastManager|"
					+ "onReceive|abortBroadcast|getResultData|setResultData");

	private static final Pattern STICKY_BROADCAST = Pattern.compile(
			"sendStickyBroadcast|sendStickyOrderedBroadcast|"
					+ "removeStickyBroadcast|STICKY_BROADCAST");
	private static final Pattern IMPLICIT_BROADCAST = Pattern.compile(
			"sendBroadcast\\s*\\(\\s*(new\\s+)?Intent\\s*\\(\\s*\"|"
					+ "sendBroadcast\\s*\\(\\s*[^,]+\\s*\\)|"
					+ "sendBroadcast\\s*\\(\\s*intent");
	private static final Pattern ORDERED_BROADCAST = Pattern.compile(
			"sendOrderedBroadcast|RESULT_RECEIVER|"
					+ "abortBroadcast\\s*\\(|getResultData\\s*\\(|setResultData\\s*\\(");
	private static final Pattern BROADCAST_SENSITIVE = Pattern.compile(
			"sendBroadcast.*(?:password|token|secret|key|credential|auth)|"
					+ "putExtra.*(?:password|token|secret|key|credential|auth).*sendBroadcast|"
					+ "sendBroadcast.*(?:password|token|secret)");
	private static final Pattern DYNAMIC_RECEIVER = Pattern.compile(
			"registerReceiver\\s*\\(|registerReceiver\\s*\\(\\s*this|"
					+ "registerReceiver\\s*\\(\\s*receiver");
	private static final Pattern LOCAL_BROADCAST = Pattern.compile(
			"LocalBroadcastManager|localBroadcastManager|"
					+ "LocalBroadcastManager\\.getInstance");

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
		new Rule(STICKY_BROADCAST, "sticky_broadcast", "high",
				"Sticky broadcast — data persists and is readable by any app; "
						+ "deprecated since API 21; use event bus or LiveData instead"),
		new Rule(BROADCAST_SENSITIVE, "broadcast_sensitive_data", "high",
				"Sensitive data in broadcast — password/token/key sent via broadcast; "
						+ "any receiver with matching intent-filter can intercept"),
		new Rule(ORDERED_BROADCAST, "ordered_broadcast_hijack", "medium",
				"Ordered broadcast — receivers with higher priority can intercept and "
						+ "modify data; verify priority ordering and data sensitivity"),
		new Rule(IMPLICIT_BROADCAST, "implicit_broadcast_send", "medium",
				"Implicit broadcast — any receiver can intercept; use explicit broadcast "
						+ "(setComponent/setClass) or LocalBroadcastManager for internal events"),
		new Rule(DYNAMIC_RECEIVER, "dynamic_receiver", "info",
				"Dynamic BroadcastReceiver registration — ensure unregistered in "
						+ "onPause/onStop to prevent leaks; prefer manifest-declared "
						+ "receivers for long-lived listening"),
		new Rule(LOCAL_BROADCAST, "local_broadcast", "info",
				"LocalBroadcastManager usage — positive indicator; broadcasts stay "
						+ "within the app and cannot be intercepted by other apps"),
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
		boolean hasStickyBroadcast = false;
		boolean hasLocalBroadcast = false;

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
			if (code == null || code.isEmpty() || !BROADCAST_MARKER.matcher(code).find()) {
				continue;
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
						if ("sticky_broadcast".equals(r.kind)) {
							hasStickyBroadcast = true;
						}
						if ("local_broadcast".equals(r.kind)) {
							hasLocalBroadcast = true;
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
		data.put("hasStickyBroadcast", hasStickyBroadcast);
		data.put("hasLocalBroadcast", hasLocalBroadcast);
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
		return "broadcast-scan";
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
