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
 * Scans decompiled code for insecure Intent / IPC usage — the MASVS MSTG-PLATFORM attack surface
 * that lives <em>in code</em>, complementing {@link ManifestAuditCommand} (static exported-component
 * flags) and {@link DeepLinkAuditCommand} (declared intent-filters). Native: reads jadx's parsed
 * model, no external tool.
 *
 * <p>The marquee detection is <b>mutable {@code PendingIntent}</b>: a {@code PendingIntent}
 * created without {@code FLAG_IMMUTABLE} (the pre-Android-12 default) is implicitly mutable, so a
 * malicious app that receives it can fill in the blank fields of the wrapped Intent and have it
 * fired with the victim app's identity and permissions — the root of a long line of real CVEs.
 * Because jadx renders the flags argument either as the named constant or as its raw int, every
 * {@code PendingIntent.get*} call site is classified by inspecting the line for
 * {@code FLAG_IMMUTABLE}/{@code 0x4000000} vs {@code FLAG_MUTABLE}/{@code 0x2000000}.
 *
 * <p>Also flags: sticky broadcasts (no access control, deprecated), bare {@code sendBroadcast} /
 * {@code sendOrderedBroadcast} (implicit broadcasts can leak data to any receiver — verify a
 * permission is supplied), dynamic {@code registerReceiver} without {@code RECEIVER_NOT_EXPORTED}/a
 * permission, implicit {@code new Intent("action")} construction, and {@code grantUriPermission} /
 * {@code FLAG_GRANT_*_URI_PERMISSION} URI grants.
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * mutablePendingIntents, truncated}}.
 */
@Command(name = "intent-scan",
		description = "Scan code for insecure Intent/IPC usage (mutable PendingIntent, sticky/implicit broadcasts, dynamic receivers, URI grants)")
public class IntentScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** A simple single-line rule (everything except the stateful PendingIntent check). */
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

	private static final Pattern PENDING_INTENT_GET =
			Pattern.compile("PendingIntent\\.get(Activity|Activities|Broadcast|Service|ForegroundService)\\s*\\(");
	// jadx may emit the named constant or the raw int. FLAG_IMMUTABLE = 0x04000000 = 67108864,
	// FLAG_MUTABLE = 0x02000000 = 33554432.
	private static final Pattern FLAG_IMMUTABLE = Pattern.compile("FLAG_IMMUTABLE|67108864");
	private static final Pattern FLAG_MUTABLE = Pattern.compile("FLAG_MUTABLE|33554432");

	private static final List<Rule> RULES = List.of(
			new Rule("sendStickyBroadcast\\s*\\(|sendStickyOrderedBroadcast\\s*\\(", "sticky_broadcast", "medium",
					"Sticky broadcast — deprecated, no access control; any app can read the broadcast data"),
			new Rule("sendBroadcast\\s*\\(|sendOrderedBroadcast\\s*\\(", "implicit_broadcast", "low",
					"Broadcast send — if the Intent is implicit and no receiverPermission is supplied, data leaks to any receiver"),
			new Rule("registerReceiver\\s*\\(", "dynamic_receiver", "low",
					"Dynamic broadcast receiver — without RECEIVER_NOT_EXPORTED or a permission it is world-reachable"),
			new Rule("new\\s+Intent\\s*\\(\\s*\"", "implicit_intent", "low",
					"Implicit Intent built from an action string — ensure no sensitive extras and set a package/component when possible"),
			new Rule("grantUriPermission\\s*\\(|FLAG_GRANT_WRITE_URI_PERMISSION|FLAG_GRANT_READ_URI_PERMISSION", "uri_grant", "info",
					"URI permission grant — verify the receiving component and that the grant is scoped/temporary"));

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
		int mutablePendingIntents = 0;

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
			if (code == null || code.isEmpty()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;

				// Stateful check first: PendingIntent mutability.
				if (PENDING_INTENT_GET.matcher(line).find()) {
					boolean immutable = FLAG_IMMUTABLE.matcher(line).find();
					boolean mutable = FLAG_MUTABLE.matcher(line).find();
					if (!immutable) {
						mutablePendingIntents++;
						if (mutable) {
							findings.add(finding(fullName, ln, "mutable_pending_intent", "medium",
									"PendingIntent created with FLAG_MUTABLE — ensure the base Intent is explicit (named component) so it can't be hijacked"));
						} else {
							findings.add(finding(fullName, ln, "mutable_pending_intent", "high",
									"PendingIntent without FLAG_IMMUTABLE — implicitly mutable; a receiving app can fill in the Intent and fire it as you (CVE-class)"));
						}
						if (findings.size() >= limit) {
							break;
						}
					}
					// A PendingIntent line is fully described by the check above; don't also run
					// the generic rules on it.
					continue;
				}

				for (Rule rule : RULES) {
					if (rule.pattern.matcher(line).find()) {
						findings.add(finding(fullName, ln, rule.kind, rule.severity, rule.detail));
						if (findings.size() >= limit) {
							break;
						}
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("mutablePendingIntents", mutablePendingIntents);
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

	@Override
	protected String getDaemonCommandName() {
		return "intent-scan";
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
