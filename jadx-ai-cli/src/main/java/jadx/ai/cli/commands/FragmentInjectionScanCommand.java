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
 *       injection via this intent extra. <b>Downgraded</b> to
 *       {@code preference_fragment_protected}/{@code info} when the class
 *       overrides {@code isValidFragment()} — that override IS the documented
 *       fix (it whitelists allowed Fragment classes), so flagging a protected
 *       app as a high-severity injection was a false positive</li>
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
	/**
	 * Cross-line form of {@link #FRAGMENT_FROM_INTENT}. When the extra is read into a local that is
	 * REUSED (e.g. logged or passed twice), jadx keeps the local and splits the two statements across
	 * lines — and renames the local after its origin (e.g. {@code stringExtra}), so the second line
	 * reads {@code Fragment.instantiate(this, stringExtra);} with NO {@code getStringExtra} token:
	 * <pre>
	 *   String stringExtra = getIntent().getStringExtra("fragment_class");  // line 1: getStringExtra, no instantiate
	 *   Fragment.instantiate(this, stringExtra);                            // line 2: instantiate, no getStringExtra
	 * </pre>
	 * Every per-line arm welds {@code instantiate} and {@code getStringExtra}/{@code getIntent} with
	 * {@code .*} on one line, so neither line matches — a silent HIGH-severity FN (attacker-controlled
	 * Fragment class). When the extra is used ONCE jadx inlines it back to a single line (caught by the
	 * per-line arms); this DOTALL pattern catches the reused-local split. Scoped by the FRAGMENT_MARKER
	 * class gate. Verified via real javac&#8594;d8&#8594;jadx. Package-private for testing.
	 */
	static final Pattern FRAGMENT_FROM_INTENT_SPLIT = Pattern.compile(
			"getStringExtra\\s*\\([^)]*\"[^\"]*\"[\\s\\S]{0,400}?Fragment\\.instantiate\\s*\\(|"
					+ "getIntent\\s*\\(\\s*\\)[\\s\\S]{0,400}?Fragment\\.instantiate\\s*\\(",
			Pattern.DOTALL);
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
	/**
	 * An override of {@code PreferenceActivity.isValidFragment(String)} — the documented mitigation for
	 * EXTRA_SHOW_FRAGMENT injection (Android < 4.4). Matches a method declaration: a method named
	 * {@code isValidFragment} taking one arg and returning boolean, with any body. Decompiled output
	 * spells it {@code public boolean isValidFragment(String fragmentName)} or {@code isValidFragment(String)}.
	 * Package-private so a test can assert the FP guard with synthetic input.
	 */
	static final Pattern IS_VALID_FRAGMENT_OVERRIDE = Pattern.compile(
			"isValidFragment\\s*\\(\\s*[A-Za-z_][^)]*\\)\\s*\\{", Pattern.DOTALL);
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
			boolean protectedByIsValidFragment = protectedByIsValidFragment(code);
			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!reportedKinds.contains(r.kind) && r.pattern.matcher(line).find()) {
						// FP guard: PreferenceActivity injection is already mitigated by an
						// isValidFragment() override — that override IS the fix. Downgrade from
						// high/injection to info/protected rather than cry wolf on hardened code.
						String kind = r.kind;
						String severity = r.severity;
						String detail = r.detail;
						if ("preference_fragment_injection".equals(r.kind) && protectedByIsValidFragment) {
							kind = "preference_fragment_protected";
							severity = "info";
							detail = "PreferenceActivity surface present but the class overrides "
									+ "isValidFragment() — the documented mitigation for EXTRA_SHOW_FRAGMENT "
									+ "injection (Android < 4.4); verify the override whitelists only expected "
									+ "Fragment classes";
						}
						findings.add(finding(kind, severity, fullName, i + 1, detail));
						reportedKinds.add(r.kind);
						if ("high".equals(severity)) {
							highSeverityCount++;
						}
						if ("fragment_from_intent".equals(kind)
								|| "preference_fragment_injection".equals(kind)) {
							hasFragmentInjection = true;
						}
						break;
					}
				}
			}
			// Cross-line fallback: when the intent extra is read into a reused local, jadx splits the
			// getStringExtra and Fragment.instantiate across lines (see FRAGMENT_FROM_INTENT_SPLIT) and
			// renames the local, so no per-line arm matches. Only fire when the per-line pass did NOT
			// already report this kind (avoid dup).
			if (!reportedKinds.contains("fragment_from_intent")
					&& findings.size() < limit
					&& FRAGMENT_FROM_INTENT_SPLIT.matcher(code).find()) {
				findings.add(finding("fragment_from_intent", "high", fullName, 0,
						"Fragment instantiated from Intent extra — attacker controls which "
								+ "Fragment class is loaded (cross-line jadx form: extra read into a "
								+ "reused local, instantiate on a separate statement); validate class "
								+ "name against a whitelist of allowed Fragments"));
				highSeverityCount++;
				hasFragmentInjection = true;
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

	/**
	 * True if the decompiled class body overrides {@code isValidFragment(String)} — the documented
	 * mitigation for EXTRA_SHOW_FRAGMENT Fragment injection. Package-private so a synthetic-input test
	 * can assert the FP guard without spinning up jadx.
	 */
	static boolean protectedByIsValidFragment(String code) {
		return code != null && IS_VALID_FRAGMENT_OVERRIDE.matcher(code).find();
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
