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
 *       privilege escalation via deep-link parameters</li>
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

	/** Gate: only scan classes with deep-link handler markers. */
	private static final Pattern DEEPLINK_MARKER = Pattern.compile(
			"getData\\s*\\(|getIntent\\s*\\(\\s*\\)\\.getData|"
					+ "ACTION_VIEW|onNewIntent|getUri|parseUri|"
					+ "getQueryParameter|getPath|getScheme|getHost|"
					+ "deeplink|deep_link|deepLink");

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

	private static final Pattern SQL_INJECTION = Pattern.compile(
			"getQueryParameter.*rawQuery|getQueryParameter.*execSQL|"
					+ "getQueryParameter.*query\\s*\\(|getData.*rawQuery|"
					+ "uri.*selection.*getQueryParameter|"
					+ "getData.*insert\\s*\\(|getData.*update\\s*\\(");
	private static final Pattern WEBVIEW_LOAD = Pattern.compile(
			"getData.*loadUrl|getData.*loadData|"
					+ "getQueryParameter.*loadUrl|uri.*loadUrl|"
					+ "getData.*WebView|uri.*WebView.*loadUrl|"
					+ "deepLink.*loadUrl|deeplink.*loadUrl");
	private static final Pattern CLASS_LOADING = Pattern.compile(
			"getQueryParameter.*Class\\.forName|getQueryParameter.*instantiate|"
					+ "getData.*Class\\.forName|getData.*Fragment\\.instantiate|"
					+ "uri.*loadClass|deeplink.*forName");
	private static final Pattern AUTH_DECISION = Pattern.compile(
			"getQueryParameter.*(?:isAdmin|isRoot|role|auth|token|session)|"
					+ "getData.*(?:isAdmin|isRoot|role|auth)|"
					+ "deeplink.*(?:token|session|auth|login)");
	private static final Pattern HANDLER = Pattern.compile(
			"getIntent\\s*\\(\\s*\\)\\.getData|getData\\s*\\(\\)|"
					+ "onNewIntent|ACTION_VIEW|getQueryParameter");

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
		new Rule(SQL_INJECTION, "deeplink_sql_injection", "high",
				"Deep-link parameter used in SQL — SQL injection via crafted URL "
						+ "parameters; use parameterized queries (selectionArgs)"),
		new Rule(WEBVIEW_LOAD, "deeplink_webview_load", "high",
				"Deep-link URL loaded in WebView — XSS/phishing via crafted URL; "
						+ "validate URL against whitelist before loading"),
		new Rule(CLASS_LOADING, "deeplink_class_loading", "high",
				"Deep-link parameter used for class loading — code injection via "
						+ "crafted URL parameter; validate class name against whitelist"),
		new Rule(AUTH_DECISION, "deeplink_auth_decision", "high",
				"Deep-link parameter used for auth decision — privilege escalation "
						+ "via crafted URL parameters; never trust URL data for auth"),
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
