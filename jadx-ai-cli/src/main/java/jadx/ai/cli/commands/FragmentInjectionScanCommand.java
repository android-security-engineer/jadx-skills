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
 * Fragment-injection scanner — MASVS MSTG-PLATFORM.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects dynamic Fragment instantiation from external input: Fragment class
 * names loaded from Intent extras, Bundle arguments, or preference storage
 * and instantiated via Fragment.instantiate or Class.forName. An attacker
 * can inject arbitrary Fragment classes within the app.
 *
 * <p>Distinct from {@code intent-redirection-scan} (intent redirection to
 * exported components) and {@code dynamic-loading-scan} (generic dynamic
 * class loading) — this scanner focuses on <b>Fragment-specific injection</b>.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code fragment_from_intent} — Fragment.instantiate with Intent extra —
 *       attacker controls which Fragment is loaded</li>
 *   <li>{@code fragment_from_bundle} — Fragment.instantiate with Bundle value —
 *       may be attacker-controlled if Bundle comes from external source</li>
 *   <li>{@code fragment_class_from_string} — Class.forName / loadClass with
 *       string variable used for Fragment — dynamic instantiation from
 *       potentially untrusted input</li>
 *   <li>{@code preference_fragment_injection} — PreferenceActivity with
 *       EXTRA_SHOW_FRAGMENT — Android < 4.4 allows arbitrary Fragment
 *       injection via this intent extra</li>
 *   <li>{@code webview_fragment} — WebView inside Fragment with JS enabled —
 *       combined attack surface</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasFragmentInjection, truncated}}.
 */
@Command(name = "fragment-injection-scan",
		description = "Detect Fragment injection attacks (MASVS MSTG-PLATFORM): dynamic Fragment from Intent extras/Bundle, Class.forName for Fragment, PreferenceActivity EXTRA_SHOW_FRAGMENT. Distinct from intent-redirection-scan and dynamic-loading-scan")
public class FragmentInjectionScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with Fragment markers. */
	private static final Pattern FRAGMENT_MARKER = Pattern.compile(
			"Fragment|FragmentTransaction|FragmentManager|fragment|"
					+ "PreferenceActivity|EXTRA_SHOW_FRAGMENT|"
					+ "instantiate|loadFragment");

	private static final Pattern FRAGMENT_FROM_INTENT = Pattern.compile(
			"Fragment\\.instantiate\\s*\\(.*getIntent|"
					+ "instantiate\\s*\\(.*getStringExtra|"
					+ "instantiate\\s*\\(.*getStringExtra|"
					+ "Fragment\\.instantiate.*intent\\.getStringExtra|"
					+ "newInstance\\s*\\(.*getIntent|"
					+ "setFragmentClass\\s*\\(.*getStringExtra");
	private static final Pattern FRAGMENT_FROM_BUNDLE = Pattern.compile(
			"Fragment\\.instantiate\\s*\\(.*getBundle|"
					+ "instantiate\\s*\\(.*getArguments|"
					+ "instantiate\\s*\\(.*Bundle|"
					+ "Fragment\\.instantiate.*bundle\\.getString");
	private static final Pattern FRAGMENT_CLASS_STRING = Pattern.compile(
			"Class\\.forName\\s*\\(.*fragment|"
					+ "loadClass\\s*\\(.*fragment|"
					+ "newInstance\\s*\\(\\s*Class\\.forName|"
					+ "fragmentClass\\s*=.*forName|"
					+ "Fragment\\.instantiate\\s*\\(.*className");
	private static final Pattern PREFERENCE_FRAGMENT = Pattern.compile(
			"EXTRA_SHOW_FRAGMENT|showFragment|"
					+ "PreferenceActivity|HEADER_ID|EXTRA_SHOW_FRAGMENT_ARGUMENTS|"
					+ "EXTRA_NO_HEADERS|VALID_FRAGMENT");
	private static final Pattern WEBVIEW_FRAGMENT = Pattern.compile(
			"WebView.*Fragment|Fragment.*WebView|"
					+ "setJavaScriptEnabled\\(true\\).*Fragment|"
					+ "Fragment.*setJavaScriptEnabled");

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
		new Rule(FRAGMENT_FROM_INTENT, "fragment_from_intent", "high",
				"Fragment instantiated from Intent extra — attacker controls which "
						+ "Fragment class is loaded; validate class name against a whitelist "
						+ "of allowed Fragments"),
		new Rule(PREFERENCE_FRAGMENT, "preference_fragment_injection", "high",
				"PreferenceActivity with EXTRA_SHOW_FRAGMENT — Android < 4.4 allows "
						+ "arbitrary Fragment injection via this intent extra; override "
						+ "isValidFragment() to whitelist allowed Fragment classes"),
		new Rule(FRAGMENT_FROM_BUNDLE, "fragment_from_bundle", "medium",
				"Fragment instantiated from Bundle — Bundle may come from external "
						+ "source; validate Fragment class name against whitelist"),
		new Rule(FRAGMENT_CLASS_STRING, "fragment_class_from_string", "medium",
				"Fragment class loaded from string variable via Class.forName/loadClass — "
						+ "if string comes from external input, arbitrary Fragment can be loaded; "
						+ "validate against whitelist"),
		new Rule(WEBVIEW_FRAGMENT, "webview_fragment", "info",
				"WebView inside Fragment with JS enabled — combined attack surface; "
						+ "ensure WebView URL source is validated"),
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
		boolean hasFragmentInjection = false;

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
			if (code == null || code.isEmpty() || !FRAGMENT_MARKER.matcher(code).find()) {
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
						if ("fragment_from_intent".equals(r.kind) || "preference_fragment_injection".equals(r.kind)) {
							hasFragmentInjection = true;
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
		data.put("hasFragmentInjection", hasFragmentInjection);
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
		return "fragment-injection-scan";
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
