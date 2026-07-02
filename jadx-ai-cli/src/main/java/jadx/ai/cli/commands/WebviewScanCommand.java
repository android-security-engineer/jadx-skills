package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Scans decompiled code for dangerous {@code WebView} configuration — the web-attack-surface class
 * of Android vulnerability (UXSS, local-file theft, JS→Java RCE, cleartext content). Distinct from
 * {@link NativeBridgeIndexCommand}, which only <em>enumerates</em> JS bridges; this command flags
 * the <em>misconfigured settings</em> that make a bridge (or the WebView itself) exploitable.
 * Native: reads jadx's parsed model, no external tool. Per-call detections over {@code WebSettings}
 * and {@code WebView}:
 * <ul>
 *   <li>{@code setAllowUniversalAccessFromFileURLs(true)} / {@code setAllowFileAccessFromFileURLs(true)}
 *       — UXSS, cross-origin local-file reads (high)</li>
 *   <li>{@code addJavascriptInterface(...)} — JS can call into Java
 *       (RCE pre-API17, still risky)</li>
 *   <li>{@code addWebMessageListener(...)} / {@code WebMessageListener} — modern two-way JS bridge
 *       (post-API-23 replacement for addJavascriptInterface); unverified origin → native method call</li>
 *   <li>{@code setAcceptThirdPartyCookies(true)} / {@code setAcceptCookie(true)} +
 *       {@code CookieManager.getCookie} — session-cookie exfiltration to web content (CWE-1004)</li>
 *   <li>{@code setAllowFileAccess(true)} / {@code setAllowContentAccess(true)} — file:// and content://
 *       reachable from web content</li>
 *   <li>{@code setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)} — https page may load http resources
 *       (jadx decompiles the constant to literal {@code 0}; the rule matches {@code setMixedContentMode(0)})</li>
 *   <li>{@code onReceivedSslError → handler.proceed()} — accepts any invalid TLS cert (trivial MITM, high)</li>
 *   <li>{@code setWebContentsDebuggingEnabled(true)} — remote debugging left on in production</li>
 *   <li>{@code setSavePassword(true)} — deprecated insecure credential storage</li>
 *   <li>{@code loadUrl("javascript:...")} — script injection / UXSS (WebView runs a javascript: URL)</li>
 *   <li>{@code loadUrl("http://...")} / {@code loadData} over cleartext</li>
 * </ul>
 */
@Command(name = "webview-scan",
		description = "Scan code for dangerous WebView configuration (file-URL access, JS bridges incl. addWebMessageListener, third-party cookie theft, mixed content (setMixedContentMode(0)), javascript: URL injection, debugging, SSL bypass)")
public class WebviewScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/**
	 * Modern two-way JS bridge — the post-API-23 replacement for {@code addJavascriptInterface}. Bypasses
	 * the js_interface rule, so a WebView that migrated to WebMessageListener looked clean. Unverified
	 * {@code allowedOriginRules}/{@code isOriginAllowed} lets any page call native methods. Package-private
	 * for testing.
	 */
	static final Pattern WEB_MESSAGE_LISTENER = Pattern.compile(
			"addWebMessageListener\\s*\\(|WebViewCompat\\.addWebMessageListener\\s*\\(|WebMessageListener|onPostMessage\\s*\\(\\s*WebMessage");

	/**
	 * WebView (third-party) cookie acceptance — combined with {@link #COOKIE_READ}, web content can
	 * exfiltrate the host app's session cookies (account takeover, CWE-1004). The {@code true} arg may
	 * follow the receiver ({@code setAcceptThirdPartyCookies(webView, true)}), so the sink is bounded by
	 * {@code [^;]*?} up to {@code true} (not the next {@code ;}) — same widening as the SQL/exec dynamic-arg
	 * rules. Package-private for testing.
	 */
	static final Pattern THIRD_PARTY_COOKIE = Pattern.compile(
			"setAcceptThirdPartyCookies\\s*\\([^;]*?true|setAcceptCookie\\s*\\(\\s*true\\s*\\)");

	/** Reads the WebView cookie jar; risky if exposed to untrusted web content. Package-private for testing. */
	static final Pattern COOKIE_READ = Pattern.compile(
			"CookieManager\\.getInstance\\s*\\(\\s*\\)\\s*\\.getCookie");

	/**
	 * {@code setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)} — https pages may load http resources (MITM).
	 * The old rule matched the {@code MIXED_CONTENT_ALWAYS_ALLOW} identifier, but {@code WebSettings}
	 * interface constants are compile-time-folded to integer literals in the bytecode; jadx therefore
	 * decompiles the call as {@code setMixedContentMode(0)} (value 0 == ALWAYS_ALLOW), with NO identifier,
	 * so the old pattern never matched any real input. Now matches the literal value 0. Package-private
	 * for testing.
	 */
	static final Pattern MIXED_CONTENT_ALWAYS_ALLOW = Pattern.compile(
			"setMixedContentMode\\s*\\(\\s*0\\s*\\)");

	/**
	 * {@code loadUrl("javascript:...")} — the WebView loads a {@code javascript:} URL, i.e. directly
	 * injects and runs a script string in the loaded page's origin (script injection / UXSS). The
	 * cleartext-load rules only covered the {@code http://} scheme; the {@code javascript:} scheme — the
	 * most common WebView JS-injection surface — was missed. Package-private for testing.
	 */
	static final Pattern JS_LOAD_URL = Pattern.compile("loadUrl\\s*\\(\\s*\"javascript:");

	// Each rule: a single-line pattern, a kind, a severity, and a human detail.
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

		Rule(String regex, String kind, String severity, String detail) {
			this(Pattern.compile(regex), kind, severity, detail);
		}
	}

	private static final List<Rule> RULES = List.of(
			new Rule("setAllowUniversalAccessFromFileURLs\\s*\\(\\s*true\\s*\\)", "universal_file_access", "high",
					"setAllowUniversalAccessFromFileURLs(true) — file:// content gets universal cross-origin access (UXSS)"),
			new Rule("setAllowFileAccessFromFileURLs\\s*\\(\\s*true\\s*\\)", "file_url_access", "high",
					"setAllowFileAccessFromFileURLs(true) — file:// content can read other local files"),
			new Rule("setAllowFileAccess\\s*\\(\\s*true\\s*\\)", "file_access", "medium",
					"setAllowFileAccess(true) — WebView can load file:// URLs"),
			new Rule("setAllowContentAccess\\s*\\(\\s*true\\s*\\)", "content_access", "low",
					"setAllowContentAccess(true) — WebView can load content:// URLs"),
			new Rule("addJavascriptInterface\\s*\\(", "js_interface", "high",
					"addJavascriptInterface(...) — exposes a Java object to JavaScript (RCE risk, esp. pre-API17)"),
			new Rule(WEB_MESSAGE_LISTENER, "web_message_listener", "medium",
					"WebMessageListener / addWebMessageListener — modern two-way JS bridge (the post-API-23 " +
							"replacement for addJavascriptInterface); bypasses the js_interface rule. Verify " +
							"allowedOriginRules / isOriginAllowed — an unverified origin lets any page call native methods"),
			new Rule(THIRD_PARTY_COOKIE, "third_party_cookie", "high",
					"setAcceptThirdPartyCookies(true) / setAcceptCookie(true) — WebView accepts (third-party) " +
							"cookies; combined with CookieManager.getCookie a malicious/injected page can exfiltrate " +
							"the host app's session cookies (incl. httpOnly http cookies) — account takeover (CWE-1004)"),
			new Rule(COOKIE_READ, "cookie_read", "medium",
					"CookieManager.getInstance().getCookie(...) — reads the WebView cookie jar; if cookies are " +
							"exposed to untrusted web content (JS enabled, third-party cookies accepted) the session " +
							"can be stolen. Review where the returned cookie string is sent"),
			new Rule("setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)", "javascript_enabled", "info",
					"setJavaScriptEnabled(true) — JS execution enabled (risk multiplier for the findings above)"),
			new Rule(MIXED_CONTENT_ALWAYS_ALLOW, "mixed_content", "high",
					"setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW) — https pages may load http resources (MITM). "
							+ "Note: the MIXED_CONTENT_ALWAYS_ALLOW constant compiles to literal 0, so jadx emits "
							+ "setMixedContentMode(0)"),
			new Rule(JS_LOAD_URL, "js_loadurl", "medium",
					"loadUrl(\"javascript:...\") — WebView loads a javascript: URL, directly injecting and running "
							+ "a script string in the loaded page's origin (script injection / UXSS)"),
			new Rule("setWebContentsDebuggingEnabled\\s*\\(\\s*true\\s*\\)", "webview_debug", "medium",
					"setWebContentsDebuggingEnabled(true) — remote WebView debugging enabled"),
			new Rule("setSavePassword\\s*\\(\\s*true\\s*\\)", "save_password", "medium",
					"setSavePassword(true) — deprecated insecure WebView credential storage"),
			new Rule("loadUrl\\s*\\(\\s*\"http://", "cleartext_load", "medium",
					"loadUrl(\"http://...\") — WebView loads cleartext content"),
			new Rule("loadData(WithBaseURL)?\\s*\\([^)]*http://", "cleartext_load", "low",
					"loadData over a cleartext http base URL"));

	// Only scan classes that actually touch WebView, to keep results focused.
	private static final Pattern WEBVIEW_MARKER = Pattern.compile("WebView|WebSettings|WebViewClient|WebChromeClient");

	// Class-level (multi-line) signal: an onReceivedSslError override that calls handler.proceed()
	// accepts ANY invalid TLS certificate — trivial MITM. The method signature and the proceed()
	// call sit on different lines, so the per-line rules above can't express it.
	private static final Pattern SSL_PROCEED = Pattern.compile("\\.proceed\\s*\\(");

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
		boolean sawJsEnabled = false;
		boolean sawJsInterface = false;
		boolean sawSslBypass = false;

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
			if (code == null || code.isEmpty() || !WEBVIEW_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule rule : RULES) {
					Matcher m = rule.pattern.matcher(line);
					if (m.find()) {
						if ("javascript_enabled".equals(rule.kind)) {
							sawJsEnabled = true;
						}
						if ("js_interface".equals(rule.kind)) {
							sawJsInterface = true;
						}
						findings.add(finding(fullName, i + 1, rule.kind, rule.severity, rule.detail));
						if (findings.size() >= limit) {
							break;
						}
					}
				}
			}

			// Class-level: onReceivedSslError override that proceeds past a cert error (spans lines).
			if (findings.size() < limit && hasSslBypass(code)) {
				findings.add(finding(fullName, lineOf(lines, ".proceed("), "ssl_error_ignored", "high",
						"onReceivedSslError calls handler.proceed() — accepts ANY invalid TLS certificate "
								+ "(trivial MITM); validate the chain and call handler.cancel() on error"));
				sawSslBypass = true;
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		// The classic JS-bridge RCE precondition: JS enabled AND a Java object exposed to it.
		data.put("jsBridgeExposed", sawJsEnabled && sawJsInterface);
		// TLS validation defeated in a WebViewClient — MITM regardless of the app's other pinning.
		data.put("sslValidationDisabled", sawSslBypass);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	/**
	 * True if a class overrides {@code onReceivedSslError} and calls {@code handler.proceed()} — the
	 * blind-accept-any-cert pattern. Requires both tokens so a correct handler that calls
	 * {@code cancel()} is not flagged.
	 */
	static boolean hasSslBypass(String code) {
		return code.contains("onReceivedSslError") && SSL_PROCEED.matcher(code).find();
	}

	/** 1-based line number of the first line containing {@code needle}, or 0 if none. */
	private static int lineOf(String[] lines, String needle) {
		for (int i = 0; i < lines.length; i++) {
			if (lines[i].contains(needle)) {
				return i + 1;
			}
		}
		return 0;
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
		return "webview-scan";
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
