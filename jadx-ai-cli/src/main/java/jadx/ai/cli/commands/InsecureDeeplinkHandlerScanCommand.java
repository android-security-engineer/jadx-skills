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
 * Insecure deep-link handler scanner — MASVS MSTG-PLATFORM.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects data-flow security issues in deep-link handlers: URL parameters
 * used for file access, SQL queries, WebView loading, class loading, or
 * authentication decisions. Distinct from {@code deeplink-scan} (deep-link
 * attack surface inventory — scheme/host/path extraction from manifest) —
 * this scanner focuses on <b>how deep-link data is used inside handlers</b>.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code deeplink_path_traversal} — URI/URL path used in file operations
 *       (openFile, FileInputStream, File constructor) — path traversal</li>
 *   <li>{@code deeplink_sql_injection} — URI query parameter used in raw SQL —
 *       SQL injection via deep-link parameters</li>
 *   <li>{@code deeplink_webview_load} — URI/URL from deep-link loaded in WebView
 *       — XSS or phishing via crafted URL</li>
 *   <li>{@code deeplink_class_loading} — URI parameter used for Class.forName or
 *       Fragment.instantiate — code injection</li>
 *   <li>{@code deeplink_auth_decision} — URI parameter used for auth decision —
 *       privilege escalation via deep-link parameters; detected across lines
 *       (class-scope deep-link source on one line flows into an auth-decision
 *       sink on another), because jadx puts the keyword on the decision line</li>
 *   <li>{@code deeplink_handler} — getIntent().getData()/getAction() in Activity —
 *       inventory of deep-link handlers</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasPathTraversal, hasSqlInjection, truncated}}.
 */
@Command(name = "insecure-deeplink-handler-scan",
		description = "Detect insecure deep-link handler data flows (MASVS MSTG-PLATFORM): path traversal, SQL injection, WebView URL loading, class loading, auth decisions from deep-link params. Distinct from deeplink-scan (attack surface inventory)")
public class InsecureDeeplinkHandlerScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/**
	 * Gate: only scan classes with deep-link handler markers. Kept in sync with {@link #DEEPLINK_SOURCE} —
	 * includes {@code getDataString} (a DEEPLINK_SOURCE anchor): jadx emits the variable form
	 * {@code intent.getDataString()} (Intent stored in a local) which does NOT match {@code getData\s*\(}
	 * (followed by {@code S}, not {@code (}) nor {@code getIntent().getData} (it's {@code intent.}, not
	 * {@code getIntent().}), so without {@code getDataString} here a handler reading the raw URI string
	 * via a local Intent variable is skipped at the gate — a silent high-severity FN on
	 * {@code deeplink_path_traversal}/{@code deeplink_sql_injection}/{@code deeplink_webview_load}/
	 * {@code deeplink_auth_decision}. Package-private for testing.
	 */
	static final Pattern DEEPLINK_MARKER = Pattern.compile(
			"getData\\s*\\(|getIntent\\s*\\(\\s*\\)\\.getData|"
					+ "ACTION_VIEW|onNewIntent|getUri|parseUri|"
					+ "getQueryParameter|getPath|getScheme|getHost|"
					+ "deeplink|deep_link|deepLink|getDataString");

	/**
	 * Deep-link untrusted-URI source — matched at <b>class scope</b>: a real deep-link handler reads
	 * the URI ({@code getData()}/{@code getQueryParameter()}/{@code getPath()}) on one line and performs
	 * the file/SQL/WebView operation on another, so a same-line {@code source.*sink} AND would miss the
	 * common form. Package-private so a test can assert the cross-line fix.
	 */
	static final Pattern DEEPLINK_SOURCE = Pattern.compile(
			"getData\\s*\\(|getQueryParameter\\s*\\(|\\.getPath\\s*\\(|\\.getScheme\\s*\\(|"
					+ "\\.getHost\\s*\\(|getUri\\s*\\(|parseUri\\s*\\(|getDataString\\s*\\(");

	/**
	 * File-operation sink — matched <b>per line</b> for the {@code lineNumber} anchor. The
	 * {@code deeplink_path_traversal} finding fires on the first FILE_SINK line of a class that also
	 * has a {@link #DEEPLINK_SOURCE} and no {@link #DEEPLINK_CANONICAL_GUARD}. Package-private for testing.
	 */
	static final Pattern FILE_SINK = Pattern.compile(
			"new\\s+File\\s*\\(|new\\s+FileInputStream\\s*\\(|new\\s+FileOutputStream\\s*\\(|"
					+ "openFile\\s*\\(|\\.writeFile|new\\s+OutputStream\\s*\\(");

	/** A path-canonicalization guard — its presence means the class defends against traversal. */
	static final Pattern DEEPLINK_CANONICAL_GUARD = Pattern.compile(
			"getCanonicalPath|getCanonicalFile|CanonicalPath|Files\\.canonicalize|\\.normalize\\s*\\(");

	/**
	 * True iff the line is a file sink and the class both takes a deep-link URI and does not canonicalize
	 * paths — the cross-line deeplink_path_traversal signal. Package-private for testing.
	 */
	static boolean deeplinkPathTraversalSignal(boolean classHasSource, boolean classGuardsPath, String line) {
		return classHasSource && !classGuardsPath
				&& line != null && FILE_SINK.matcher(line).find();
	}

	/**
	 * SQL sinks reachable from a deep-link parameter — matched <b>per line</b> when the class also has
	 * a {@link #DEEPLINK_SOURCE}. The old same-line {@code getQueryParameter.*rawQuery} AND missed the
	 * cross-line form ({@code String q = uri.getQueryParameter("q"); db.rawQuery(q, null)}).
	 * Package-private for testing.
	 */
	static final Pattern SQL_SINK = Pattern.compile(
			"\\.rawQuery\\s*\\(|\\.execSQL\\s*\\(|\\.query\\s*\\(|\\.insert\\s*\\(|\\.update\\s*\\(");

	/**
	 * WebView URL sinks reachable from a deep-link parameter — per line when the class has a
	 * {@link #DEEPLINK_SOURCE}. Covers the cross-line form
	 * ({@code Uri u = getIntent().getData(); webView.loadUrl(u.toString())}).
	 */
	static final Pattern WEBVIEW_SINK = Pattern.compile(
			"\\.loadUrl\\s*\\(|\\.loadData\\s*\\(|\\.loadDataWithBaseURL\\s*\\(");

	/**
	 * Class-loading sinks reachable from a deep-link parameter — per line when the class has a
	 * {@link #DEEPLINK_SOURCE}. Covers {@code Class.forName}/{@code Fragment.instantiate}/
	 * {@code loadClass} fed by a deep-link value on another line.
	 */
	static final Pattern CLASS_LOAD_SINK = Pattern.compile(
			"Class\\.forName\\s*\\(|Fragment\\.instantiate\\s*\\(|\\.loadClass\\s*\\(");

	/**
	 * True iff the line is a deep-link-driven sink and the class takes a deep-link URI — the cross-line
	 * deeplink_sink signal (sql / webview / class-load). The sink line stays the per-line anchor.
	 * Package-private for testing.
	 */
	static boolean deeplinkSinkSignal(boolean classHasDeepLinkSource, String line) {
		if (!classHasDeepLinkSource || line == null) {
			return false;
		}
		return SQL_SINK.matcher(line).find()
				|| WEBVIEW_SINK.matcher(line).find()
				|| CLASS_LOAD_SINK.matcher(line).find();
	}
	/**
	 * Auth-decision sink reachable from a deep-link parameter — matched <b>per line</b> when the class also
	 * has a {@link #DEEPLINK_SOURCE}. The old same-line {@code AUTH_DECISION} AND
	 * ({@code getQueryParameter.*(?:isAdmin|role|auth|token|session)}) only fired when the source
	 * extraction and the auth check shared a line; the common jadx form is cross-line
	 * ({@code String role = uri.getQueryParameter("role");} then {@code if (role.equals("admin")) { grantAdmin(); }},
	 * or {@code String t = uri.getQueryParameter("t"); verify(t);} where the keyword lives on the decision line,
	 * not the extraction line). Package-private for testing.
	 */
	static final Pattern AUTH_DECISION_SINK = Pattern.compile(
			"(?:isAdmin|isRoot|isAuthenticated|isLoggedIn|hasPermission|grantAdmin|elevate|setRole|"
					+ "verifyToken|validateToken|checkPermission|setPrivilege|setAccessLevel|"
					+ "switchUser|becomeAdmin|grantPermission|authorize)"
					+ "\\s*\\(|"
					+ "(?:role|auth|token|session|privilege|accessLevel|permission)"
					+ "\\s*\\.\\s*(?:equals|equalsIgnoreCase|compareTo|contains)\\s*\\(|"
					+ "\"(?:admin|root|superuser|authenticated|granted|allowed)\"\\s*\\.\\s*(?:equals|equalsIgnoreCase)");

	private static final Pattern HANDLER = Pattern.compile(
			"getIntent\\s*\\(\\s*\\)\\.getData|getData\\s*\\(\\)|"
					+ "onNewIntent|ACTION_VIEW|getQueryParameter");

	/**
	 * True iff the line is an auth-decision sink reached from a deep-link parameter on another line —
	 * the cross-line deeplink_auth_decision signal. Package-private for testing.
	 */
	static boolean deeplinkAuthDecisionSignal(boolean classHasDeepLinkSource, String line) {
		return classHasDeepLinkSource && line != null && AUTH_DECISION_SINK.matcher(line).find();
	}

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
		// deeplink_path_traversal is handled separately (class-scoped DEEPLINK_SOURCE ∧ per-line
		// FILE_SINK) — see deeplinkPathTraversalSignal below — because jadx decompiles the source and
		// the file sink onto different lines, which a same-line .* AND would miss.
		// deeplink_sql_injection / deeplink_webview_load / deeplink_class_loading are likewise handled
		// separately (class-scoped DEEPLINK_SOURCE ∧ per-line SQL_SINK/WEBVIEW_SINK/CLASS_LOAD_SINK) —
		// see deeplinkSinkSignal — for the same cross-line reason.
		// deeplink_auth_decision is likewise handled separately (class-scoped DEEPLINK_SOURCE ∧ per-line
		// AUTH_DECISION_SINK) — see deeplinkAuthDecisionSignal — for the same cross-line reason.
		new Rule(HANDLER, "deeplink_handler", "info",
				"Deep-link handler — Activity receives and processes deep-link data; "
						+ "ensure all URI data is validated before use"),
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
		boolean hasPathTraversal = false;
		boolean hasSqlInjection = false;

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
			if (code == null || code.isEmpty() || !DEEPLINK_MARKER.matcher(code).find()) {
				continue;
			}

			// DEEPLINK_SOURCE and the canonical-path guard are matched at CLASS scope: a real handler
			// reads the URI on one line and opens the file on another, so a same-line source.*sink AND
			// would miss it. The FILE_SINK line stays the per-line anchor for lineNumber.
			boolean classHasDeepLinkSource = DEEPLINK_SOURCE.matcher(code).find();
			boolean classGuardsPath = DEEPLINK_CANONICAL_GUARD.matcher(code).find();

			// Per-line rule detection (first-match-wins, ONE/class per kind)
			TreeSet<String> reportedKinds = new TreeSet<>();
			boolean reportedPathTraversal = false;
			boolean reportedAuthDecision = false;
			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				// Class-scoped deeplink_path_traversal: first FILE_SINK line of a class that takes a
				// deep-link URI and does not canonicalize. Covers both the same-line and the cross-line
				// (Uri data = getIntent().getData(); ... new File(data.getPath())) forms.
				if (!reportedPathTraversal
						&& deeplinkPathTraversalSignal(classHasDeepLinkSource, classGuardsPath, line)) {
					findings.add(finding("deeplink_path_traversal", "high", fullName, i + 1,
							"Deep-link URI used in file operations — path traversal via crafted "
									+ "URL path (e.g. myapp://host/../../../data); validate and "
									+ "canonicalize paths before file access"));
					reportedPathTraversal = true;
					reportedKinds.add("deeplink_path_traversal");
					highSeverityCount++;
					hasPathTraversal = true;
					continue;
				}

				// Class-scoped deeplink sinks (sql / webview / class-load): the first matching sink
				// line of a class that takes a deep-link URI. Covers both the same-line (method-chain)
				// and the cross-line (Uri u = getData(); webView.loadUrl(u.toString())) forms.
				if (deeplinkSinkSignal(classHasDeepLinkSource, line)) {
					if (!reportedKinds.contains("deeplink_sql_injection")
							&& SQL_SINK.matcher(line).find()) {
						findings.add(finding("deeplink_sql_injection", "high", fullName, i + 1,
								"Deep-link parameter used in SQL — SQL injection via crafted URL "
										+ "parameters; use parameterized queries (selectionArgs)"));
						reportedKinds.add("deeplink_sql_injection");
						highSeverityCount++;
						hasSqlInjection = true;
					} else if (!reportedKinds.contains("deeplink_webview_load")
							&& WEBVIEW_SINK.matcher(line).find()) {
						findings.add(finding("deeplink_webview_load", "high", fullName, i + 1,
								"Deep-link URL loaded in WebView — XSS/phishing via crafted URL; "
										+ "validate URL against whitelist before loading"));
						reportedKinds.add("deeplink_webview_load");
						highSeverityCount++;
					} else if (!reportedKinds.contains("deeplink_class_loading")
							&& CLASS_LOAD_SINK.matcher(line).find()) {
						findings.add(finding("deeplink_class_loading", "high", fullName, i + 1,
								"Deep-link parameter used for class loading — code injection via "
										+ "crafted URL parameter; validate class name against whitelist"));
						reportedKinds.add("deeplink_class_loading");
						highSeverityCount++;
					}
					continue;
				}

				// Class-scoped deeplink_auth_decision: first AUTH_DECISION_SINK line of a class that
				// takes a deep-link URI. Covers the cross-line form jadx emits — the keyword lives on
				// the decision line, not the URI-extraction line:
				//   String role = uri.getQueryParameter("role");  // source line, no auth keyword
				//   if (role.equals("admin")) { grantAdmin(); }   // sink line, the auth decision
				if (!reportedAuthDecision
						&& deeplinkAuthDecisionSignal(classHasDeepLinkSource, line)) {
					findings.add(finding("deeplink_auth_decision", "high", fullName, i + 1,
							"Deep-link parameter used for auth decision — privilege escalation "
									+ "via crafted URL parameters; never trust URL data for auth, "
									+ "verify against server-side state"));
					reportedAuthDecision = true;
					reportedKinds.add("deeplink_auth_decision");
					highSeverityCount++;
					continue;
				}

				for (Rule r : RULES) {
					if (!reportedKinds.contains(r.kind) && r.pattern.matcher(line).find()) {
						findings.add(finding(r.kind, r.severity, fullName, i + 1, r.detail));
						reportedKinds.add(r.kind);
						if ("high".equals(r.severity)) {
							highSeverityCount++;
						}
						if ("deeplink_path_traversal".equals(r.kind)) {
							hasPathTraversal = true;
						}
						if ("deeplink_sql_injection".equals(r.kind)) {
							hasSqlInjection = true;
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
		data.put("hasPathTraversal", hasPathTraversal);
		data.put("hasSqlInjection", hasSqlInjection);
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
		return "insecure-deeplink-handler-scan";
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
