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
 *       clear, vulnerable to MITM</li>
 *   <li>{@code no_hostname_verify} — {@code setHostnameVerifier(ALLOW_ALL)} or
 *       custom HostnameVerifier that always returns true — does not verify the server
 *       certificate matches the expected hostname</li>
 *   <li>{@code insecure_okhttp} — OkHttp client built without TLS configuration
 *       ({@code OkHttpClient.Builder()} without {@code .sslSocketFactory()} or
 *       {@code .hostnameVerifier()})</li>
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
		description = "Detect network-traffic security issues (MASVS MSTG-NETWORK-1/2): cleartext HTTP URLs, no hostname verification, insecure OkHttp/Retrofit config, trust-all X509TrustManager. Distinct from ssl-scan (TLS implementation) and network-security-config (NSC policy)")
public class NetworkTrafficScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes that make network requests. */
	private static final Pattern NETWORK_MARKER = Pattern.compile(
			"http://|https://|HttpURLConnection|OkHttpClient|Retrofit|URLConnection|"
					+ "HostnameVerifier|setHostnameVerifier|TrustManager|X509TrustManager|"
					+ "sslSocketFactory|connectTimeout|readTimeout");

	private static final Pattern HTTP_URL = Pattern.compile("\"http://[^\"]+\"");
	private static final Pattern ALLOW_ALL_VERIFIER = Pattern.compile(
			"ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier\\s*\\(.*ALLOW_ALL|"
					+ "HostnameVerifier\\s*\\{.*return\\s+true");
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
		new Rule(HTTP_URL, "cleartext_http", "medium",
				"Hardcoded http:// URL — data sent in the clear without encryption; vulnerable "
						+ "to MITM interception; use https:// instead"),
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
		return args;
	}
}
