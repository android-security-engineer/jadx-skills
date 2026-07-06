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
 * WebView URL-source security scanner — MASVS MSTG-PLATFORM-2.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code webview-scan} (WebView security configuration — JS enabled,
 * file access, mixed content, JS interfaces). This scanner focuses on <b>the source of
 * URLs loaded into WebViews</b>: whether the URL comes from an untrusted source (Intent
 * extra, external input) and whether the WebView properly validates/whitelists URLs
 * before loading them.
 *
 * <p>Categories (first-match-wins per line):
 * <ul>
 *   <li>{@code url_from_intent} — {@code loadUrl()} called with a URL obtained from
 *       {@code getIntent().getStringExtra()} / {@code getData()} — an attacker controls
 *       the URL via a deep link or exported activity</li>
 *   <li>{@code url_redirect} — {@code shouldOverrideUrlLoading()} that loads a new URL
 *       without validation — open-redirect risk; an attacker can redirect the WebView
 *       to a malicious page</li>
 *   <li>{@code url_no_whitelist} — WebView that loads URLs but has no host/scheme
 *       whitelist check in the same class — any URL can be loaded</li>
 *   <li>{@code url_whitelist} — WebView with host/scheme validation (defence inventory)</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasWhitelist, truncated}}.
 */
@Command(name = "webview-url-scan",
		description = "Detect WebView URL-source security issues (MASVS MSTG-PLATFORM-2): URLs from Intent extras/data, open-redirect in shouldOverrideUrlLoading, missing URL whitelist. Distinct from webview-scan (WebView security configuration)")
public class WebViewUrlScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes that load URLs in WebViews. */
	private static final Pattern WEBVIEW_URL_MARKER = Pattern.compile(
			"loadUrl|shouldOverrideUrlLoading|WebView");

	private static final Pattern LOAD_URL = Pattern.compile(
			"\\.loadUrl\\s*\\(");
	private static final Pattern URL_FROM_INTENT = Pattern.compile(
			"getIntent\\s*\\(\\s*\\)\\.getStringExtra|getIntent\\s*\\(\\s*\\)\\.getData|"
					+ "getIntent\\s*\\(\\s*\\)\\.getParcelableExtra|getIntent\\s*\\(\\s*\\)\\.getBundleExtra|"
					+ "intent\\.getStringExtra|intent\\.getData|"
					+ "getUri|getExtra.*[Uu]rl");
	private static final Pattern SHOULD_OVERRIDE = Pattern.compile(
			"shouldOverrideUrlLoading");
	private static final Pattern NEW_LOAD_IN_OVERRIDE = Pattern.compile(
			"loadUrl\\s*\\(|loadData\\s*\\(|loadDataWithBaseURL\\s*\\(");
	/** Whitelist/validation patterns. */
	private static final Pattern WHITELIST = Pattern.compile(
			"contains\\s*\\(|startsWith\\s*\\(|endsWith\\s*\\(|equals\\s*\\(|"
					+ "indexOf\\s*\\(|matches\\s*\\(|Pattern\\.compile|"
					+ "ALLOWED_HOSTS|ALLOWED_DOMAINS|WHITELIST|whitelist|allowedHosts|allowedDomains|"
					+ "getHost\\s*\\(|getScheme\\s*\\(");

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
		boolean hasWhitelist = false;

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
			if (code == null || code.isEmpty() || !WEBVIEW_URL_MARKER.matcher(code).find()) {
				continue;
			}

			// Class-level checks
			boolean classHasLoadUrl = LOAD_URL.matcher(code).find();
			boolean classHasUrlFromIntent = URL_FROM_INTENT.matcher(code).find();
			boolean classHasWhitelist = WHITELIST.matcher(code).find();
			boolean classHasShouldOverride = SHOULD_OVERRIDE.matcher(code).find();

			if (classHasWhitelist) {
				hasWhitelist = true;
			}

			// Per-line detection
			boolean reportedUrlFromIntent = false;
			boolean reportedRedirect = false;
			boolean reportedNoWhitelist = false;

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				// URL from Intent loaded into WebView
				if (!reportedUrlFromIntent && LOAD_URL.matcher(line).find()
						&& classHasUrlFromIntent) {
					findings.add(finding("url_from_intent", "high", fullName, i + 1,
							"WebView.loadUrl() with URL from Intent extra/data — an attacker controls "
									+ "the URL via deep link or exported activity; add URL whitelist validation "
									+ "before loading"));
					highSeverityCount++;
					reportedUrlFromIntent = true;
					continue;
				}

				// Open redirect in shouldOverrideUrlLoading
				if (!reportedRedirect && SHOULD_OVERRIDE.matcher(line).find()) {
					// Check if this method loads a new URL
					boolean loadsNewUrl = false;
					for (int j = i + 1; j < Math.min(i + 20, lines.length); j++) {
						if (NEW_LOAD_IN_OVERRIDE.matcher(lines[j]).find()) {
							loadsNewUrl = true;
							break;
						}
						if (lines[j].trim().equals("}") || lines[j].contains("return ")) {
							break;
						}
					}
					if (loadsNewUrl && !classHasWhitelist) {
						findings.add(finding("url_redirect", "high", fullName, i + 1,
								"shouldOverrideUrlLoading loads a new URL without validation — "
										+ "open-redirect risk; an attacker can redirect the WebView to a "
										+ "malicious page; validate the URL host/scheme before loading"));
						highSeverityCount++;
						reportedRedirect = true;
					}
					continue;
				}

				// No whitelist in WebView class
				if (!reportedNoWhitelist && classHasLoadUrl && !classHasWhitelist
						&& LOAD_URL.matcher(line).find()) {
					findings.add(finding("url_no_whitelist", "medium", fullName, i + 1,
							"WebView loads URLs without host/scheme whitelist validation — "
									+ "any URL can be loaded; add a whitelist check (getHost/startsWith) "
									+ "before loadUrl()"));
					reportedNoWhitelist = true;
				}
			}

			// Whitelist defence inventory
			if (classHasLoadUrl && classHasWhitelist) {
				findings.add(finding("url_whitelist", "info", fullName, 0,
						"WebView with URL whitelist/validation present — defence against "
								+ "arbitrary URL loading"));
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("hasWhitelist", hasWhitelist);
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
		return "webview-url-scan";
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
