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
import jadx.api.ResourceFile;
import jadx.api.ResourceType;

/**
 * Network-traffic security scanner — MASVS MSTG-NETWORK-1/2.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code ssl-scan} (SSL/TLS implementation defects — trust-all TrustManagers,
 * ALLOW_ALL hostname verifiers) and {@code network-security-config} (NSC policy inventory).
 * This scanner focuses on <b>application-layer network request security</b>: cleartext HTTP
 * traffic, insecure URL connections, hostname verification disabled at the connection level,
 * and OkHttp/Retrofit misconfigurations.
 *
 * <p>Categories (first-match-wins per line):
 * <ul>
 *   <li>{@code cleartext_http} — {@code http://} URL in code (not https) — data sent in the
 *       clear, vulnerable to MITM. Also catches the bare {@code "http://"} scheme assembled
 *       at runtime ({@code "http://" + host}), not just complete URL literals</li>
 *   <li>{@code no_hostname_verify} — {@code setHostnameVerifier(ALLOW_ALL)}, the deprecated
 *       {@code ALLOW_ALL_HOSTNAME_VERIFIER} constant, or an anonymous {@code HostnameVerifier}
 *       that unconditionally returns true — does not verify the server certificate matches the
 *       expected hostname</li>
 *   <li>{@code insecure_okhttp} — OkHttp client built without TLS configuration
 *       ({@code OkHttpClient.Builder()} without {@code .sslSocketFactory()} or
 *       {@code .hostnameVerifier()})</li>
 *   <li>{@code insecure_okhttp_cleartext} — OkHttp {@code ConnectionSpec.CLEARTEXT} — an
 *       explicit cleartext-only connection spec (the modern OkHttp opt-in to unencrypted HTTP)</li>
 *   <li>{@code insecure_retrofit} — Retrofit builder with {@code http://} base URL —
 *       all API calls go over cleartext</li>
 *   <li>{@code trust_all_x509} — {@code TrustAllManager} / custom X509TrustManager that
 *       does nothing in checkServerTrusted — trusts any certificate</li>
 *   <li>{@code connection_timeout_low} — Very low connection/read timeouts that may
 *       enable timing attacks or DoS amplification</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasCleartextTraffic, truncated}}.
 */
@Command(name = "network-traffic-scan",
		description = "Detect network-traffic security issues (MASVS MSTG-NETWORK-1/2): cleartext HTTP URLs (incl. bare \"http://\" scheme), anonymous HostnameVerifier returning true, ALLOW_ALL verifier, OkHttp CLEARTEXT spec / no-TLS builder, Retrofit http base URL, trust-all X509TrustManager. Distinct from ssl-scan (TLS implementation) and network-security-config (NSC policy)")
public class NetworkTrafficScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	@Option(names = { "--no-resources" }, description = "Skip strings.xml/ARSC resources (scan code only)")
	protected boolean noResources;

	/** Gate: only scan classes that make network requests. */
	private static final Pattern NETWORK_MARKER = Pattern.compile(
			"http://|https://|HttpURLConnection|OkHttpClient|Retrofit|URLConnection|"
					+ "HostnameVerifier|setHostnameVerifier|TrustManager|X509TrustManager|"
					+ "sslSocketFactory|connectTimeout|readTimeout");

	private static final Pattern HTTP_URL = Pattern.compile("\"http://[^\"]+\"");
	/**
	 * A bare {@code "http://"} scheme — not a full URL string (e.g. {@code "http://" + host},
	 * {@code "http://".concat(host)}, or a {@code "http://"} constant). {@link #HTTP_URL} requires a
	 * complete {@code "http://..."} literal, so dynamically-assembled cleartext schemes were missed.
	 * Catches the concatenated/constant form. Package-private for testing.
	 */
	static final Pattern HTTP_URL_BARE = Pattern.compile("\"http://\"\\s*\\+|\"http://\"\\.concat|=\\s*\"http://\"");
	/**
	 * OkHttp {@code ConnectionSpec.CLEARTEXT} — an explicit cleartext-only connection spec, the modern
	 * OkHttp way to opt a host into unencrypted HTTP. Was previously suppressed: the
	 * {@code connectionSpecs} token is listed in {@link #OKHTTP_SSL} as a *safe* signal, so a builder
	 * that calls {@code .connectionSpecs(ConnectionSpec.CLEARTEXT)} was treated as TLS-configured and
	 * the cleartext spec went unreported. Now reported as its own finding independent of the
	 * OkHttp-Builder-without-TLS check. Package-private for testing.
	 */
	static final Pattern CLEARTEXT_SPEC = Pattern.compile("ConnectionSpec\\.CLEARTEXT(?!_AND_TLS)");
	/**
	 * Application-layer signals that hostname verification is disabled: the deprecated
	 * {@code ALLOW_ALL_HOSTNAME_VERIFIER} constant, and a {@code setHostnameVerifier(ALLOW_ALL...)}
	 * install call. Both are per-line. The anonymous-{@code HostnameVerifier}-returning-true form
	 * ({@code new HostnameVerifier() { ... return true; }}) is matched separately at CLASS scope by
	 * {@link #ANON_HOSTNAME_VERIFIER_TRUE} (DOTALL) because jadx decompiles it across multiple lines
	 * and the old per-line {@code HostnameVerifier\s*\{.*return true} arm was dead code — it required
	 * {@code \{} to follow {@code HostnameVerifier} immediately, but Java syntax is
	 * {@code HostnameVerifier()} (with a parameter list). Package-private for testing.
	 */
	static final Pattern ALLOW_ALL_VERIFIER = Pattern.compile(
			"ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\\s*\\(.*ALLOW_ALL");

	/**
	 * An anonymous {@code HostnameVerifier} subclass whose body unconditionally returns true — the
	 * classic custom-verifier bypass. Matched at CLASS scope (DOTALL) because jadx emits the anonymous
	 * class across multiple lines; the parameter list after {@code HostnameVerifier} is required so a
	 * real verifier ({@code return host.equals(h);}) does not fire. Package-private for testing.
	 */
	static final Pattern ANON_HOSTNAME_VERIFIER_TRUE = Pattern.compile(
			"HostnameVerifier\\s*\\([^)]*\\)\\s*\\{.*return\\s+true\\s*;", Pattern.DOTALL);
	private static final Pattern OKHTTP_BUILDER = Pattern.compile("OkHttpClient\\.Builder");
	private static final Pattern OKHTTP_SSL = Pattern.compile(
			"sslSocketFactory|hostnameVerifier|connectionSpecs|certificatePinner");
	private static final Pattern RETROFIT_HTTP = Pattern.compile(
			"Retrofit\\.Builder|new\\s+Retrofit\\.Builder|retrofit2\\.Retrofit");
	private static final Pattern RETROFIT_BASE_HTTP = Pattern.compile(
			"baseUrl\\s*\\(\\s*\"http://");
	private static final Pattern TRUST_ALL = Pattern.compile(
			"TrustAllManager|TrustAllTrustManager|checkServerTrusted\\s*\\(\\s*[^)]*\\)\\s*\\{\\s*\\}|"
					+ "checkServerTrusted\\s*\\(\\s*[^)]*\\)\\s*\\{\\s*//\\s*trust\\s+all");
	private static final Pattern LOW_TIMEOUT = Pattern.compile(
			"connectTimeout\\s*\\(\\s*[0-9]+\\s*,|readTimeout\\s*\\(\\s*[0-9]+\\s*,|"
					+ "setConnectTimeout\\s*\\(\\s*[0-9]+\\)|setReadTimeout\\s*\\(\\s*[0-9]+\\)");

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
		new Rule(ALLOW_ALL_VERIFIER, "no_hostname_verify", "high",
				"ALLOW_ALL hostname verifier / custom verifier returning true — does not verify "
						+ "the server certificate matches the expected hostname; enables MITM attacks"),
		new Rule(TRUST_ALL, "trust_all_x509", "high",
				"Trust-all X509TrustManager — checkServerTrusted does nothing; accepts any "
						+ "server certificate including self-signed and forged; enables MITM attacks"),
		new Rule(RETROFIT_BASE_HTTP, "insecure_retrofit", "high",
				"Retrofit base URL uses http:// — all API calls go over cleartext; change to "
						+ "https:// to encrypt traffic"),
		new Rule(CLEARTEXT_SPEC, "insecure_okhttp_cleartext", "medium",
				"OkHttp ConnectionSpec.CLEARTEXT — explicit cleartext-only connection spec; all "
						+ "requests for this host go over unencrypted HTTP; remove the CLEARTEXT spec or "
						+ "use CLEARTEXT_AND_TLS only as a fallback"),
		new Rule(HTTP_URL, "cleartext_http", "medium",
				"Hardcoded http:// URL — data sent in the clear without encryption; vulnerable "
						+ "to MITM interception; use https:// instead"),
		new Rule(HTTP_URL_BARE, "cleartext_http", "medium",
				"Hardcoded \"http://\" scheme concatenated/constant — cleartext URL assembled at "
						+ "runtime; data sent without encryption; vulnerable to MITM; use https://"),
		new Rule(LOW_TIMEOUT, "connection_timeout_low", "info",
				"Very low connection/read timeout configured — may cause reliability issues or "
						+ "enable timing-based attacks; verify the timeout values are appropriate"),
	};

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
		Object nr = args.get("noResources");
		if (nr != null) {
			this.noResources = Boolean.TRUE.equals(nr) || "true".equals(nr.toString());
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();
		int highSeverityCount = 0;
		boolean hasCleartextTraffic = false;

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
			if (code == null || code.isEmpty() || !NETWORK_MARKER.matcher(code).find()) {
				continue;
			}

			// Class-level checks
			boolean classHasOkHttpBuilder = OKHTTP_BUILDER.matcher(code).find();
			boolean classHasOkHttpSsl = OKHTTP_SSL.matcher(code).find();
			boolean classHasRetrofit = RETROFIT_HTTP.matcher(code).find();
			boolean classHasHttpUrl = HTTP_URL.matcher(code).find();

			if (classHasHttpUrl) {
				hasCleartextTraffic = true;
			}

			// Anonymous HostnameVerifier that unconditionally returns true — class-level (DOTALL)
			// because jadx emits the anonymous class across multiple lines. The old per-line arm
			// was dead (required '{' to follow HostnameVerifier immediately; Java syntax is
			// HostnameVerifier() with a parameter list). Report before the insecure_okhttp early-out
			// so a TLS-configured builder that also installs a bypass verifier still fires.
			if (findings.size() < limit && ANON_HOSTNAME_VERIFIER_TRUE.matcher(code).find()) {
				findings.add(finding("no_hostname_verify", "high", fullName, 0,
						"Anonymous HostnameVerifier that unconditionally returns true — does not verify "
								+ "the server certificate matches the expected hostname; enables MITM attacks"));
				highSeverityCount++;
			}

			// OkHttp without TLS config
			if (classHasOkHttpBuilder && !classHasOkHttpSsl) {
				findings.add(finding("insecure_okhttp", "medium", fullName, 0,
						"OkHttpClient.Builder without sslSocketFactory/hostnameVerifier/"
								+ "certificatePinner — uses platform defaults which may be "
								+ "insufficient; explicitly configure TLS and certificate pinning"));
				continue; // already reported for this class
			}

			// Per-line rule detection
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
						if ("cleartext_http".equals(r.kind)) {
							hasCleartextTraffic = true;
						}
						break;
					}
				}
			}
		}

		// Resource scan: a cleartext http:// URL stored in strings.xml/ARSC and loaded via
		// getString(R.string.x) NEVER appears in code as a literal, so the class-loop above (gated by
		// NETWORK_MARKER requiring an in-code http:// token) skips the whole class — a silent FN that
		// also masked the cleartext traffic from hasCleartextTraffic. Scan resources directly. ONE/url.
		TreeSet<String> reportedResUrls = new TreeSet<>();
		if (!noResources) {
			for (ResourceFile res : decompiler.getResources()) {
				if (findings.size() >= limit) {
					break;
				}
				ResourceType type = res.getType();
				if (type != ResourceType.XML && type != ResourceType.ARSC && type != ResourceType.MANIFEST) {
					continue;
				}
				try {
					var container = res.loadContent();
					if (container == null) {
						continue;
					}
					var codeInfo = container.getText();
					if (codeInfo == null) {
						continue;
					}
					String text = codeInfo.toString();
					var m = HTTP_URL.matcher(text);
					while (m.find() && findings.size() < limit) {
						String url = m.group();
						if (reportedResUrls.add(url)) {
							findings.add(finding("cleartext_http", "medium", res.getOriginalName(), 0,
									"Cleartext http:// URL stored in a string resource (loaded via "
											+ "getString(R.string.*)) — sent over HTTP; move to https:// and "
											+ "enforce NSC cleartext-off"));
							hasCleartextTraffic = true;
						}
					}
				} catch (Exception ignored) {
					// skip unreadable resources
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("hasCleartextTraffic", hasCleartextTraffic);
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
		return "network-traffic-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		if (noResources) {
			args.put("noResources", true);
		}
		return args;
	}
}
