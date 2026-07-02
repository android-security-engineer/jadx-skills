package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.SecretPatterns;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;

/**
 * Analyzes a Cordova / PhoneGap / Ionic / Capacitor hybrid app — the class of Android app whose
 * entire logic is HTML/JS under {@code assets/www/} running inside a privileged WebView. Absorbs the
 * design idea from hybrid-app auditors (which flag the Cordova network/navigation whitelist and the
 * page CSP, the two controls that decide whether a compromised page can pivot into native plugins)
 * and reimplements it natively over jadx's resource API.
 *
 * <p>Why no existing command covers this: {@code framework-detect} only name-matches Cordova assets,
 * and {@code webview-scan}/{@code secrets-scan}/{@code ioc-extract} read decompiled <em>Java</em> —
 * none of them open {@code config.xml} or the {@code assets/www/**} HTML/JS where the real logic,
 * the whitelist, the CSP, and almost every hardcoded secret live. This command reads those files.</p>
 *
 * <p>Findings:</p>
 * <ul>
 *   <li>{@code access_origin_wildcard} (high) — {@code <access origin="*"/>}: the network whitelist
 *       lets the app reach any origin (data exfiltration / loading attacker content).</li>
 *   <li>{@code navigation_wildcard} (high) — {@code <allow-navigation href="*"/>}: the WebView may
 *       navigate to any URL, loading remote content into the plugin-privileged context (RCE pivot).</li>
 *   <li>{@code intent_wildcard} (medium) — {@code <allow-intent href="*"/>}.</li>
 *   <li>{@code cleartext_whitelist} (medium) — a whitelist entry over {@code http://} (MITM).</li>
 *   <li>{@code csp_missing} (high) / {@code csp_unsafe} (high) — no page CSP, or one allowing
 *       {@code unsafe-inline}/{@code unsafe-eval}/{@code *} (XSS in the privileged WebView).</li>
 *   <li>bundle secrets + URLs recovered from the {@code www} JavaScript.</li>
 * </ul>
 */
@Command(name = "cordova-analysis",
		description = "Analyze a Cordova/Ionic/Capacitor hybrid app: config.xml whitelist, page CSP, plugins, and secrets/URLs in assets/www")
public class CordovaAnalysisCommand extends AbstractCommand {

	@Option(names = { "--min-entropy" }, description = "Min Shannon entropy for generic secret detection in www JS", defaultValue = "4.0")
	protected double minEntropy = 4.0;

	@Option(names = { "--limit" }, description = "Maximum secrets/URLs to return", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern ACCESS_ORIGIN = Pattern.compile("<access\\b[^>]*\\borigin\\s*=\\s*\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);
	private static final Pattern ALLOW_NAV = Pattern.compile("<allow-navigation\\b[^>]*\\bhref\\s*=\\s*\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);
	private static final Pattern ALLOW_INTENT = Pattern.compile("<allow-intent\\b[^>]*\\bhref\\s*=\\s*\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);
	private static final Pattern PLUGIN_ID = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
	private static final Pattern CSP_META = Pattern.compile(
			"<meta\\b[^>]*http-equiv\\s*=\\s*\"Content-Security-Policy\"[^>]*content\\s*=\\s*\"([^\"]*)\"",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
	private static final Pattern HTTP_URL = Pattern.compile("\\bhttps?://[^\\s\"'`\\\\<>)}\\];,]+");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("min_entropy") && args.get("min_entropy") != null) {
			this.minEntropy = ((Number) args.get("min_entropy")).doubleValue();
		}
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		String configXml = null;
		String indexHtml = null;
		boolean hasWww = false;
		boolean hasCordovaJs = false;
		boolean hasCapacitor = false;
		List<String> pluginFiles = new ArrayList<>();
		List<String> plugins = new ArrayList<>();
		StringBuilder wwwJs = new StringBuilder();

		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name == null) {
				continue;
			}
			String norm = name.replace('\\', '/');
			String base = norm.substring(norm.lastIndexOf('/') + 1);
			boolean inWww = norm.contains("assets/www/") || norm.contains("/www/") || norm.startsWith("www/");
			if (inWww) {
				hasWww = true;
			}
			if (base.equals("cordova.js") || base.equals("cordova_plugins.js") || base.equals("phonegap.js")) {
				hasCordovaJs = true;
			}
			if (base.equals("capacitor.config.json") || base.equals("capacitor.config.xml") || norm.contains("capacitor.plugins")) {
				hasCapacitor = true;
			}

			if (base.equals("config.xml") && configXml == null) {
				configXml = readText(res);
				continue;
			}
			if (base.equals("cordova_plugins.js")) {
				pluginFiles.add(norm);
				String js = readText(res);
				if (js != null) {
					Matcher pm = PLUGIN_ID.matcher(js);
					while (pm.find() && plugins.size() < 200) {
						String id = pm.group(1);
						if (!plugins.contains(id)) {
							plugins.add(id);
						}
					}
				}
				continue;
			}
			if (inWww && base.equals("index.html") && indexHtml == null) {
				indexHtml = readText(res);
			}
			// Collect www JavaScript for secret/URL scanning (cap total size to stay bounded).
			if (inWww && base.endsWith(".js") && wwwJs.length() < 4_000_000) {
				String js = readText(res);
				if (js != null) {
					wwwJs.append(js).append('\n');
				}
			}
		}

		boolean isCordova = hasWww || hasCordovaJs || hasCapacitor || configXml != null;

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("isCordova", isCordova);
		data.put("hasWww", hasWww);
		data.put("hasCordovaJs", hasCordovaJs);
		data.put("hasCapacitor", hasCapacitor);
		data.put("hasConfigXml", configXml != null);
		data.put("plugins", plugins);
		data.put("pluginCount", plugins.size());

		List<Map<String, Object>> findings = new ArrayList<>();

		if (configXml != null) {
			// Network whitelist (<access origin=>).
			for (String origin : allValues(ACCESS_ORIGIN, configXml)) {
				if (isWildcard(origin)) {
					findings.add(finding("access_origin_wildcard", "high",
							"<access origin=\"" + origin + "\"> — network whitelist allows any origin (data exfiltration / loading attacker content)"));
				} else if (isCleartext(origin)) {
					findings.add(finding("cleartext_whitelist", "medium",
							"<access origin=\"" + origin + "\"> — whitelisted over cleartext http (MITM)"));
				}
			}
			// Navigation whitelist (<allow-navigation href=>) — the RCE-pivot control.
			for (String href : allValues(ALLOW_NAV, configXml)) {
				if (isWildcard(href)) {
					findings.add(finding("navigation_wildcard", "high",
							"<allow-navigation href=\"" + href + "\"> — WebView may navigate anywhere; remote content loads into the plugin-privileged context (RCE pivot)"));
				} else if (isCleartext(href)) {
					findings.add(finding("cleartext_whitelist", "medium",
							"<allow-navigation href=\"" + href + "\"> — navigation allowed over cleartext http (MITM)"));
				}
			}
			for (String href : allValues(ALLOW_INTENT, configXml)) {
				if (isWildcard(href)) {
					findings.add(finding("intent_wildcard", "medium",
							"<allow-intent href=\"" + href + "\"> — any external intent may be launched"));
				}
			}
		}

		// Page CSP — only meaningful when we actually found the entry HTML.
		if (indexHtml != null) {
			String csp = cspContent(indexHtml);
			if (csp == null) {
				findings.add(finding("csp_missing", "high",
						"index.html has no Content-Security-Policy meta tag — inline script / remote script injection is unrestricted (XSS in privileged WebView)"));
				data.put("csp", null);
			} else {
				data.put("csp", csp);
				if (cspIsUnsafe(csp)) {
					findings.add(finding("csp_unsafe", "high",
							"Content-Security-Policy allows unsafe-inline/unsafe-eval or a wildcard source — XSS in the privileged WebView is not mitigated"));
				}
			}
		}

		// Secrets + URLs from the www JavaScript — content the Java-only scanners never open.
		List<Map<String, Object>> secrets = new ArrayList<>();
		List<String> urls = new ArrayList<>();
		if (wwwJs.length() > 0) {
			String js = wwwJs.toString();
			SecretPatterns.scanText(js, "assets/www", "www-js", minEntropy, limit, secrets);
			Matcher um = HTTP_URL.matcher(js);
			while (um.find() && urls.size() < limit) {
				String u = um.group();
				if (!urls.contains(u)) {
					urls.add(u);
				}
			}
		}
		long cleartextUrls = urls.stream().filter(u -> u.startsWith("http://")).count();

		data.put("findings", findings);
		data.put("findingCount", findings.size());
		data.put("secrets", secrets);
		data.put("secretCount", secrets.size());
		data.put("urls", urls);
		data.put("urlCount", urls.size());
		data.put("cleartextUrlCount", cleartextUrls);
		// Silent-truncation signal: secrets (capped at `limit` inside SecretPatterns.scanText), urls
		// (capped at `limit` via while-guard), and plugins (hardcoded cap at 200, independent of
		// --limit — a latent quirk: re-running with a higher limit does NOT surface more plugins).
		// Without this flag the AI believes the www-JS secret/URL/plugin set is complete when it isn't.
		data.put("truncated", secrets.size() >= limit || urls.size() >= limit || plugins.size() >= 200);

		if (isCordova) {
			List<String> notes = new ArrayList<>();
			notes.add("Hybrid app — logic is HTML/JS in assets/www running in a WebView; audit the JS and the config.xml whitelist, not just the Java shell");
			if (!secrets.isEmpty()) {
				notes.add(secrets.size() + " candidate secret(s) in the www JavaScript — invisible to Java-only secret scanners");
			}
			if (cleartextUrls > 0) {
				notes.add(cleartextUrls + " cleartext http:// URL(s) in the www JavaScript");
			}
			data.put("notes", notes);
		}
		return JsonOutput.ok(data);
	}

	private static String readText(ResourceFile res) {
		try {
			var container = res.loadContent();
			if (container != null && container.getText() != null) {
				return container.getText().toString();
			}
		} catch (Exception e) {
			// ignore — treated as unreadable
		}
		return null;
	}

	/** All capture-group-1 values of {@code p} over {@code text}. */
	private static List<String> allValues(Pattern p, String text) {
		List<String> out = new ArrayList<>();
		Matcher m = p.matcher(text);
		while (m.find()) {
			out.add(m.group(1));
		}
		return out;
	}

	/** A whitelist value that matches everything: {@code *} or a scheme-wildcard like {@code *://*}. */
	static boolean isWildcard(String value) {
		if (value == null) {
			return false;
		}
		String v = value.trim();
		return v.equals("*") || v.equals("*/*") || v.matches("(?i)\\*://\\*.*") || v.matches("(?i)https?://\\*/?\\*?");
	}

	/** A whitelist value scoped to cleartext http (not https, not wildcard). */
	static boolean isCleartext(String value) {
		if (value == null) {
			return false;
		}
		String v = value.trim().toLowerCase(java.util.Locale.ROOT);
		return v.startsWith("http://") && !isWildcard(value);
	}

	/** The {@code content} of the CSP {@code <meta>} tag, or null if there is none. */
	static String cspContent(String html) {
		if (html == null) {
			return null;
		}
		Matcher m = CSP_META.matcher(html);
		return m.find() ? m.group(1).trim() : null;
	}

	/** True if the CSP permits inline/eval script or a wildcard script/default source. */
	static boolean cspIsUnsafe(String csp) {
		if (csp == null) {
			return false;
		}
		String c = csp.toLowerCase(java.util.Locale.ROOT);
		if (c.contains("unsafe-inline") || c.contains("unsafe-eval")) {
			return true;
		}
		// A bare "*" as default-src/script-src source (not e.g. "*.example.com").
		return c.matches(".*(default-src|script-src)[^;]*\\s\\*(\\s|;|$).*");
	}

	private static Map<String, Object> finding(String kind, String severity, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "cordova-analysis";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("min_entropy", minEntropy);
		args.put("limit", limit);
		return args;
	}
}
