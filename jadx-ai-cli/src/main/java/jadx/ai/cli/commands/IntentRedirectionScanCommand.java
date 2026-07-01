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
 * Intent-redirection / confused-deputy scanner — CWE-927, the vulnerability Google Play explicitly
 * warns about. MASVS MSTG-PLATFORM. Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code intent-scan} (mutable PendingIntent, sticky/implicit broadcasts) and
 * {@code manifest-audit} (static exported flags). The redirection pattern is a <em>data flow</em>:
 * the app pulls a nested {@code Intent} out of an <b>incoming, attacker-controllable</b> Intent
 * ({@code getParcelableExtra(...)} / {@code getParcelable(...)} / {@code Intent.parseUri(...)}) and
 * then launches it ({@code startActivity}/{@code startService}/{@code sendBroadcast}/
 * {@code sendStickyBroadcast}/{@code bindService}/{@code setResult}). A malicious app can hand the victim an Intent aimed at the victim's own
 * <em>non-exported</em> components — the victim becomes a confused deputy that proxies the access.
 *
 * <p>Heuristic (class-scoped): a class that both extracts a nested Intent ({@code classHasSource}) and
 * launches an Intent ({@code classLaunches}) is flagged {@code intent_redirection/high} on its first
 * launch sink (one per class). The source set covers single-Parcelable extras
 * ({@code getParcelableExtra}/{@code getParcelable}) AND the array / array-list variants
 * ({@code getParcelableArrayExtra}/{@code getParcelableArrayListExtra}) — an attacker can smuggle a
 * nested Intent as an element of a {@code Parcelable[]} / {@code ArrayList<Parcelable>} just as well as
 * a single value, and the victim iterates and launches it. {@code Intent.parseUri(...)} on untrusted
 * data is flagged {@code unsafe_intent_parse/medium} on each occurrence (parsing an attacker URI into an
 * Intent is itself risky — it can set component/flags). {@code setResult(...,intent)} returning an
 * extracted Intent is {@code result_redirection/medium}.
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * redirectionClasses, usesIntentParseUri, truncated}}.
 */
@Command(name = "intent-redirection-scan",
		description = "Detect Intent redirection / confused-deputy (CWE-927, Google Play-flagged): a nested Intent extracted from an incoming Intent (getParcelableExtra / getParcelable / getParcelableArrayExtra / getParcelableArrayListExtra / Intent.parseUri) is then launched (startActivity/startService/sendBroadcast/sendStickyBroadcast/bindService/setResult), proxying access to non-exported components. Not covered by intent-scan")
public class IntentRedirectionScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/**
	 * Extracting a nested Intent from incoming (untrusted) data — the redirection source. Covers the
	 * single-Parcelable extractors AND the array / array-list variants: {@code getParcelableArrayExtra}
	 * returns a {@code Parcelable[]} and {@code getParcelableArrayListExtra} an
	 * {@code ArrayList<Parcelable>}; an attacker can smuggle a nested Intent as one element of either,
	 * and the victim iterates and launches it. The bare {@code getParcelable\s*\(} term does NOT match
	 * these — the char after {@code getParcelable} is {@code A}, not {@code (} — so without explicit
	 * terms the array/list redirection sources were silently missed.
	 *
	 * <p>Package-private so a synthetic-input test can assert the source set.
	 */
	static final Pattern INTENT_SOURCE = Pattern.compile(
			"getParcelableExtra\\s*\\(|getParcelable\\s*\\(|getParcelableArrayExtra\\s*\\(|"
					+ "getParcelableArrayListExtra\\s*\\(|IntentCompat\\.getParcelableExtra|Intent\\.parseUri\\s*\\(");

	/**
	 * Launching with an Intent — the redirection sink. Includes the sticky-broadcast variants
	 * ({@code sendStickyBroadcast}/{@code sendStickyOrderedBroadcast}) — a sticky broadcast of an
	 * extracted nested Intent proxies access just as a plain broadcast does, and the old sink set
	 * silently missed them. Package-private so a test can assert the sticky forms are sinks.
	 */
	static final Pattern LAUNCH_SINK = Pattern.compile(
			"startActivity\\s*\\(|startActivityForResult\\s*\\(|startActivities\\s*\\(|startService\\s*\\(|"
					+ "startForegroundService\\s*\\(|sendBroadcast\\s*\\(|sendOrderedBroadcast\\s*\\(|"
					+ "sendStickyBroadcast\\s*\\(|sendStickyOrderedBroadcast\\s*\\(|bindService\\s*\\(");

	private static final Pattern PARSE_URI = Pattern.compile("Intent\\.parseUri\\s*\\(");
	/** Two-arg setResult(int, Intent) returns an Intent to the caller; one-arg setResult(int) does not. */
	private static final Pattern SET_RESULT_INTENT = Pattern.compile("setResult\\s*\\([^,)]*,");

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
		int redirectionClasses = 0;
		boolean usesIntentParseUri = false;

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
			// Gate: a class can only redirect if it extracts a nested Intent at all.
			if (code == null || code.isEmpty() || !INTENT_SOURCE.matcher(code).find()) {
				continue;
			}

			boolean classLaunches = LAUNCH_SINK.matcher(code).find();
			String[] lines = code.split("\n", -1);
			boolean reportedRedirect = false;

			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				if (PARSE_URI.matcher(line).find()) {
					usesIntentParseUri = true;
					findings.add(finding("unsafe_intent_parse", "medium", fullName, i + 1,
							"Intent.parseUri() on untrusted data builds an Intent whose component/flags are attacker-controlled — validate the resolved target and strip GRANT/component before launching"));
					continue;
				}

				if (classLaunches && !reportedRedirect && LAUNCH_SINK.matcher(line).find()) {
					findings.add(finding("intent_redirection", "high", fullName, i + 1,
							"Class extracts a nested Intent from an incoming Intent and launches an Intent — confused-deputy redirection (CWE-927); a malicious app can reach this app's non-exported components. Verify the forwarded Intent is not the extracted one, or check its component/package"));
					highSeverityCount++;
					reportedRedirect = true;
					redirectionClasses++;
					continue;
				}

				if (SET_RESULT_INTENT.matcher(line).find()) {
					findings.add(finding("result_redirection", "medium", fullName, i + 1,
							"setResult() returns an Intent to the caller — if it is the extracted nested Intent, the caller gains the URI grants / component access this app holds"));
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("redirectionClasses", redirectionClasses);
		data.put("usesIntentParseUri", usesIntentParseUri);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String kind, String severity, String cls, int line, String detail) {
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
		return "intent-redirection-scan";
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
