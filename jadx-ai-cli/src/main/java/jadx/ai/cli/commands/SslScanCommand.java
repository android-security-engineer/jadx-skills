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

	// The declaration head of a trust-manager callback, up to the ')' of its parameter list. Used to
	// locate the body via balanced-brace matching so we can inspect a NON-empty body that the
	// whitespace-only EMPTY_CHECK_* regexes miss (e.g. "{ return; }", "{ Log.d(...); }").
	private static final Pattern CHECK_SERVER_DECL = Pattern.compile("checkServerTrusted\\s*\\([^)]*\\)");
	private static final Pattern CHECK_CLIENT_DECL = Pattern.compile("checkClientTrusted\\s*\\([^)]*\\)");
	// A body that contains ANY of these is doing (or delegating) real validation, so it is NOT a
	// blanket trust-all: `throw` rejects bad certs; a delegated checkServer/ClientTrusted or a
	// checkValidity/verify call propagates the platform's rejection. Absence of all of them means the
	// callback silently returns for every certificate — the classic non-empty trust-all stub.
	private static final Pattern VALIDATION_SIGNAL = Pattern.compile(
			"\\bthrow\\b|checkServerTrusted|checkClientTrusted|checkValidity|checkTrusted|isTrusted|\\bverify\\s*\\(");

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

		// Non-empty but still-trust-all bodies: the callback returns for every cert without throwing
		// or delegating. EMPTY_CHECK_* only catch the whitespace-only "{ }" form; these catch the
		// "{ return; }" / "{ Log.d(...); }" variants that are just as insecure.
		for (int off : nonThrowingTrustBody(code, CHECK_SERVER_DECL)) {
			if (findings.size() >= limit) {
				break;
			}
			findings.add(finding(cls, lineNumberAt(code, off), "trust_all_manager", "high",
					"checkServerTrusted() never throws and does not delegate — TrustManager accepts ALL server certificates (MITM)"));
		}
		for (int off : nonThrowingTrustBody(code, CHECK_CLIENT_DECL)) {
			if (findings.size() >= limit) {
				break;
			}
			findings.add(finding(cls, lineNumberAt(code, off), "trust_all_manager", "medium",
					"checkClientTrusted() never throws and does not delegate — client-auth validation disabled"));
		}

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

	/**
	 * Offsets of every {@code check*Trusted} method (matched by {@code decl}) whose body neither
	 * throws nor delegates to a validator — i.e. a non-empty trust-all stub. Whitespace-only bodies
	 * are skipped here because the {@code EMPTY_CHECK_*} regexes already report them, avoiding a
	 * double finding. Package-private so a same-package test can drive it with synthetic sources.
	 */
	static List<Integer> nonThrowingTrustBody(String code, Pattern decl) {
		List<Integer> hits = new ArrayList<>();
		Matcher m = decl.matcher(code);
		while (m.find()) {
			int open = code.indexOf('{', m.end());
			if (open < 0) {
				continue;
			}
			int close = matchBrace(code, open);
			if (close < 0) {
				continue;
			}
			String body = code.substring(open + 1, close);
			if (body.trim().isEmpty()) {
				continue; // handled by EMPTY_CHECK_*; don't double-report
			}
			if (!VALIDATION_SIGNAL.matcher(body).find()) {
				hits.add(m.start());
			}
		}
		return hits;
	}

	/**
	 * Index of the {@code '}'} matching the {@code '{'} at {@code openIdx}, honoring string, char,
	 * and comment context so a brace inside a literal or comment does not throw off the depth count.
	 * Returns -1 if unbalanced. Package-private for testing.
	 */
	static int matchBrace(String s, int openIdx) {
		int depth = 0;
		boolean inStr = false, inChar = false, inLine = false, inBlock = false;
		for (int i = openIdx; i < s.length(); i++) {
			char c = s.charAt(i);
			char n = i + 1 < s.length() ? s.charAt(i + 1) : '\0';
			if (inLine) {
				if (c == '\n') {
					inLine = false;
				}
			} else if (inBlock) {
				if (c == '*' && n == '/') {
					inBlock = false;
					i++;
				}
			} else if (inStr) {
				if (c == '\\') {
					i++;
				} else if (c == '"') {
					inStr = false;
				}
			} else if (inChar) {
				if (c == '\\') {
					i++;
				} else if (c == '\'') {
					inChar = false;
				}
			} else if (c == '/' && n == '/') {
				inLine = true;
				i++;
			} else if (c == '/' && n == '*') {
				inBlock = true;
				i++;
			} else if (c == '"') {
				inStr = true;
			} else if (c == '\'') {
				inChar = true;
			} else if (c == '{') {
				depth++;
			} else if (c == '}') {
				depth--;
				if (depth == 0) {
					return i;
				}
			}
		}
		return -1;
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
