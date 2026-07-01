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
 *   <li>{@code setJavaScriptEnabled(true)} + {@code addJavascriptInterface(...)} — JS can call into Java
 *       (RCE pre-API17, still risky)</li>
 *   <li>{@code setAllowFileAccess(true)} / {@code setAllowContentAccess(true)} — file:// and content://
 *       reachable from web content</li>
 *   <li>{@code setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)} — https page may load http resources</li>
 *   <li>{@code setWebContentsDebuggingEnabled(true)} — remote debugging left on in production</li>
 *   <li>{@code setSavePassword(true)} — deprecated insecure credential storage</li>
 *   <li>{@code loadUrl("http://...")} / {@code loadData} over cleartext</li>
 * </ul>
 */
@Command(name = "webview-scan",
		description = "Scan code for dangerous WebView configuration (file-URL access, JS bridges, mixed content, debugging)")
public class WebviewScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	// Each rule: a single-line pattern, a kind, a severity, and a human detail.
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
			new Rule("setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)", "javascript_enabled", "info",
					"setJavaScriptEnabled(true) — JS execution enabled (risk multiplier for the findings above)"),
			new Rule("MIXED_CONTENT_ALWAYS_ALLOW", "mixed_content", "high",
					"setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW) — https pages may load http resources (MITM)"),
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
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		// The classic JS-bridge RCE precondition: JS enabled AND a Java object exposed to it.
		data.put("jsBridgeExposed", sawJsEnabled && sawJsInterface);
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
