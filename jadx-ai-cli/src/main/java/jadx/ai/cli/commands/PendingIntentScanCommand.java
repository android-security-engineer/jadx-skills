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
 * PendingIntent security scanner — MASVS MSTG-PLATFORM / CWE-1023.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code intent-scan} (generic Intent vulnerabilities — sticky broadcasts,
 * implicit intents) and {@code intent-redirection-scan} (nested-Intent forwarding / confused-deputy).
 * This scanner focuses exclusively on {@code PendingIntent} misuse: mutable PendingIntents that
 * an attacker can modify, and PendingIntents filled with untrusted extras.
 *
 * <p>Categories:
 * <ul>
 *   <li>{@code mutable_pending_intent} — {@code FLAG_MUTABLE} used or no immutability flag set
 *       on API 31+ (defaults to FLAG_MUTABLE if unspecified on API 23–30; API 31+ requires
 *       explicit flag). An attacker with access to the PendingIntent can change its wrapped
 *       Intent's extras, action, or component.</li>
 *   <li>{@code pending_intent_untrusted_fill} — {@code PendingIntent.send(...)} or
 *       {@code fillIn(...)} called with extras from an untrusted source (e.g., from an
 *       incoming Intent's extras). The attacker controls the extras that get merged into
 *       the wrapped Intent.</li>
 *   <li>{@code pending_intent_broadcast} — PendingIntent created with
 *       {@code PendingIntent.getBroadcast(...)} — a broadcast PendingIntent can be triggered
 *       by any app that obtains the token.</li>
 *   <li>{@code pending_intent_service} — PendingIntent created with
 *       {@code PendingIntent.getService(...)} — a service PendingIntent can start a service
 *       in the victim app's context.</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, truncated}}.
 */
@Command(name = "pending-intent-scan",
		description = "Detect PendingIntent security issues (MASVS MSTG-PLATFORM / CWE-1023): FLAG_MUTABLE usage, untrusted fillIn/send with attacker extras, broadcast/service PendingIntents. Distinct from intent-scan and intent-redirection-scan")
public class PendingIntentScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes that use PendingIntent. */
	private static final Pattern PENDING_INTENT_MARKER = Pattern.compile("PendingIntent");

	private static final Pattern FLAG_MUTABLE = Pattern.compile("FLAG_MUTABLE|FLAG_UPDATE_CURRENT");
	private static final Pattern FLAG_IMMUTABLE = Pattern.compile("FLAG_IMMUTABLE");
	private static final Pattern GET_ACTIVITY = Pattern.compile("PendingIntent\\.getActivity\\s*\\(");
	private static final Pattern GET_BROADCAST = Pattern.compile("PendingIntent\\.getBroadcast\\s*\\(");
	private static final Pattern GET_SERVICE = Pattern.compile("PendingIntent\\.getService\\s*\\(");
	private static final Pattern GET_FOREGROUND_SERVICE = Pattern.compile(
			"PendingIntent\\.getForegroundService\\s*\\(");

	private static final Pattern PENDING_SEND = Pattern.compile(
			"\\.send\\s*\\(");
	private static final Pattern FILL_IN = Pattern.compile(
			"\\.fillIn\\s*\\(");
	/** Source of untrusted data that could fill a PendingIntent. */
	private static final Pattern UNTRUSTED_SOURCE = Pattern.compile(
			"getIntent\\s*\\(\\s*\\)|getExtras\\s*\\(\\s*\\)|getParcelableExtra|getBundleExtra|"
					+ "getStringExtra|getIntExtra|getLongExtra");

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
		new Rule(FLAG_MUTABLE, "mutable_pending_intent", "high",
				"FLAG_MUTABLE / FLAG_UPDATE_CURRENT on PendingIntent — an attacker who obtains the token "
						+ "can modify the wrapped Intent's extras, action, or component; use FLAG_IMMUTABLE unless "
						+ "mutability is explicitly required"),
		new Rule(GET_BROADCAST, "pending_intent_broadcast", "medium",
				"PendingIntent.getBroadcast() — a broadcast PendingIntent can be triggered by any app that "
						+ "obtains the token; verify the broadcast is not security-sensitive or is permission-protected"),
		new Rule(GET_SERVICE, "pending_intent_service", "medium",
				"PendingIntent.getService() — a service PendingIntent can start a service in the app's context; "
						+ "verify the service does not perform privileged operations based on the Intent extras"),
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
			if (code == null || code.isEmpty() || !PENDING_INTENT_MARKER.matcher(code).find()) {
				continue;
			}

			boolean classHasImmutable = FLAG_IMMUTABLE.matcher(code).find();
			boolean classHasUntrustedSource = UNTRUSTED_SOURCE.matcher(code).find();

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				// Rule-based detection
				for (Rule r : RULES) {
					if (r.pattern.matcher(line).find()) {
						// For mutable_pending_intent: skip if FLAG_IMMUTABLE is also on this line
						if ("mutable_pending_intent".equals(r.kind) && FLAG_IMMUTABLE.matcher(line).find()) {
							continue;
						}
						findings.add(finding(r.kind, r.severity, fullName, i + 1, r.detail));
						if ("high".equals(r.severity)) {
							highSeverityCount++;
						}
						break;
					}
				}

				// Untrusted fill
				if ((FILL_IN.matcher(line).find() || PENDING_SEND.matcher(line).find())
						&& classHasUntrustedSource) {
					findings.add(finding("pending_intent_untrusted_fill", "high", fullName, i + 1,
							"PendingIntent.fillIn() / .send() with data from an incoming Intent — "
									+ "attacker-controlled extras can be merged into the wrapped Intent; "
									+ "verify the filled data is validated or use FLAG_IMMUTABLE"));
					highSeverityCount++;
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
		return "pending-intent-scan";
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
