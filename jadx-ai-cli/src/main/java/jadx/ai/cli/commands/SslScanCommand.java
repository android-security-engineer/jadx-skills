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
 * Scans decompiled code for insecure TLS/SSL trust configurations — the disabled-certificate-
 * validation class of MITM vulnerability that neither {@link CryptoScanCommand} (cipher misuse)
 * nor {@link NetworkSecurityConfigCommand} (the NSC XML) covers. This is the static backing for
 * the {@code network-analysis} workflow's "is transport security actually enforced?" question.
 * Native: reads jadx's parsed model, no external tool. Detects the canonical bypasses:
 * <ul>
 *   <li>all-trusting {@code X509TrustManager}: empty {@code checkServerTrusted}/{@code checkClientTrusted}
 *       bodies, {@code getAcceptedIssuers} returning {@code null}/empty</li>
 *   <li>permissive hostname verification: {@code verify(...) { return true; }},
 *       {@code ALLOW_ALL_HOSTNAME_VERIFIER}, {@code AllowAllHostnameVerifier}</li>
 *   <li>WebView TLS errors swallowed: {@code onReceivedSslError} that calls {@code handler.proceed()}</li>
 *   <li>setters that install the above ({@code setHostnameVerifier}/{@code setDefaultHostnameVerifier}
 *       in a class that also references an all-trusting verifier)</li>
 * </ul>
 */
@Command(name = "ssl-scan",
		description = "Scan code for insecure TLS/SSL trust (all-trusting TrustManager, ALLOW_ALL hostname verifier, onReceivedSslError proceed)")
public class SslScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	// Empty trust-manager method bodies — the textbook "trust everything" stub. DOTALL so the
	// (whitespace-only) body can span the decompiler's pretty-printed newlines.
	private static final Pattern EMPTY_CHECK_SERVER = Pattern.compile(
			"checkServerTrusted\\s*\\([^)]*\\)\\s*(?:throws[\\w\\s,.]*?)?\\{\\s*\\}", Pattern.DOTALL);
	private static final Pattern EMPTY_CHECK_CLIENT = Pattern.compile(
			"checkClientTrusted\\s*\\([^)]*\\)\\s*(?:throws[\\w\\s,.]*?)?\\{\\s*\\}", Pattern.DOTALL);
	private static final Pattern ACCEPTED_ISSUERS_NULL = Pattern.compile(
			"getAcceptedIssuers\\s*\\(\\s*\\)\\s*\\{\\s*return\\s+(?:null|new\\s+X509Certificate\\s*\\[\\s*0\\s*\\])", Pattern.DOTALL);

	// Hostname verification that always passes.
	private static final Pattern VERIFY_TRUE = Pattern.compile(
			"\\bverify\\s*\\([^)]*\\)\\s*\\{\\s*return\\s+true\\s*;\\s*\\}", Pattern.DOTALL);
	private static final Pattern ALLOW_ALL_VERIFIER = Pattern.compile(
			"ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NullHostnameVerifier|NoopHostnameVerifier");

	// WebView TLS error suppression: onReceivedSslError handler that proceeds anyway.
	private static final Pattern SSL_ERROR = Pattern.compile("onReceivedSslError");
	private static final Pattern PROCEED = Pattern.compile("\\.proceed\\s*\\(");

	// Setters that wire a custom verifier/socket factory in.
	private static final Pattern SET_VERIFIER = Pattern.compile(
			"setHostnameVerifier\\s*\\(|setDefaultHostnameVerifier\\s*\\(");

	// Context marker so we only treat a bare verify()->true as TLS-related when the class is.
	private static final Pattern TLS_MARKER = Pattern.compile(
			"HostnameVerifier|TrustManager|SSLContext|SSLSocketFactory|X509|javax\\.net\\.ssl|onReceivedSslError");

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
			if (code == null || code.isEmpty()) {
				continue;
			}
			boolean tlsClass = TLS_MARKER.matcher(code).find();
			scanClass(code, fullName, tlsClass, findings);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private void scanClass(String code, String cls, boolean tlsClass, List<Map<String, Object>> findings) {
		addMatch(code, EMPTY_CHECK_SERVER, cls, "trust_all_manager", "high",
				"Empty checkServerTrusted() — TrustManager accepts ALL server certificates (MITM)", findings);
		addMatch(code, EMPTY_CHECK_CLIENT, cls, "trust_all_manager", "medium",
				"Empty checkClientTrusted() — client-auth validation disabled", findings);
		addMatch(code, ACCEPTED_ISSUERS_NULL, cls, "trust_all_manager", "high",
				"getAcceptedIssuers() returns null/empty — companion of a trust-all TrustManager", findings);
		addMatch(code, ALLOW_ALL_VERIFIER, cls, "hostname_verifier", "high",
				"ALLOW_ALL / AllowAll / Noop hostname verifier — hostname check disabled (MITM)", findings);

		if (tlsClass) {
			addMatch(code, VERIFY_TRUE, cls, "hostname_verifier", "high",
					"HostnameVerifier.verify() unconditionally returns true — hostname check disabled (MITM)", findings);
		}

		// WebView: onReceivedSslError that proceeds past the error.
		if (findings.size() < limit && SSL_ERROR.matcher(code).find() && PROCEED.matcher(code).find()) {
			findings.add(finding(cls, lineOf(code, SSL_ERROR.matcher(code)), "webview_ssl_error", "high",
					"onReceivedSslError calls handler.proceed() — WebView ignores invalid TLS certs (MITM)"));
		}
		// Custom verifier installation, only interesting alongside an all-trusting verifier in the class.
		if (findings.size() < limit && SET_VERIFIER.matcher(code).find() && ALLOW_ALL_VERIFIER.matcher(code).find()) {
			findings.add(finding(cls, lineOf(code, SET_VERIFIER.matcher(code)), "verifier_install", "medium",
					"Installs an all-trusting hostname verifier via setHostnameVerifier/setDefaultHostnameVerifier"));
		}
	}

	private void addMatch(String code, Pattern pattern, String cls, String kind, String severity,
			String detail, List<Map<String, Object>> findings) {
		Matcher m = pattern.matcher(code);
		while (m.find() && findings.size() < limit) {
			findings.add(finding(cls, lineNumberAt(code, m.start()), kind, severity, detail));
		}
	}

	private static int lineOf(String code, Matcher m) {
		return m.find() ? lineNumberAt(code, m.start()) : -1;
	}

	/** 1-based line number of a character offset. */
	private static int lineNumberAt(String code, int offset) {
		int line = 1;
		int end = Math.min(offset, code.length());
		for (int i = 0; i < end; i++) {
			if (code.charAt(i) == '\n') {
				line++;
			}
		}
		return line;
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
		return "ssl-scan";
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
