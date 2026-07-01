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
 * Log info-leak scanner — MASVS MSTG-STORAGE-3.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects sensitive data written to logs: passwords, tokens, PII,
 * cryptographic material, and auth headers in Log/Log.d/Log.e/Log.i/Log.w/Log.v
 * and System.out/err, AND in third-party logging frameworks ({@code Timber.},
 * {@code Logger.}) that {@code logging-scan} already inventories. Distinct from
 * {@code logging-scan} (logging framework inventory and debug-log presence) — this
 * scanner focuses on <b>what sensitive data is being logged</b>, not whether
 * logging is present.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code log_password} — Log.* with password variable/name — leaks
 *       credentials to Logcat (readable by any app with READ_LOGS)</li>
 *   <li>{@code log_token} — Log.* with token/session/auth variable — leaks
 *       session credentials to Logcat</li>
 *   <li>{@code log_pii} — Log.* with email/phone/ssn/name variable — leaks
 *       personally identifiable information to Logcat</li>
 *   <li>{@code log_crypto_material} — Log.* with key/cipher/signature variable
 *       — leaks cryptographic material to Logcat</li>
 *   <li>{@code log_auth_header} — Log.* with Authorization/Cookie header —
 *       leaks HTTP auth credentials to Logcat</li>
 *   <li>{@code log_intent_extras} — Log.* with getIntent().getExtras() or
 *       Bundle.toString() — may leak sensitive intent data to Logcat</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasCredentialLeak, hasPiiLeak, truncated}}.
 */
@Command(name = "log-info-leak-scan",
		description = "Detect sensitive data leaked to logs (MASVS MSTG-STORAGE-3): passwords, tokens, PII, crypto material, auth headers in Log/System.out. Distinct from logging-scan (framework inventory)")
public class LogInfoLeakScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/**
	 * A logging-sink prefix shared by the gate, the call check, and every classification rule so that
	 * third-party frameworks ({@code Timber.<level>(}, {@code Logger.<level>(}) — which
	 * {@code logging-scan} already inventories — are classified here too, not just {@code Log.*} /
	 * {@code System.out/err}. Without this, {@code Timber.d("token="+token)} got only the coarse
	 * {@code sensitive_log} from {@code logging-scan} and missed the finer {@code log_token} here.
	 * Package-private so a test can assert framework logs are classified.
	 */
	static final String LOG_SINK_PREFIX =
			"(?:Log\\.[a-z]+|Timber\\.[a-z]+|Logger\\.[a-z]+)\\s*\\(|System\\.(?:out|err)\\.print(?:ln)?\\s*\\(|println\\s*\\(";

	/** Gate: only scan classes with log statements. */
	private static final Pattern LOG_MARKER = Pattern.compile(
			"Log\\.(d|e|i|v|w|wtf)\\(|System\\.out\\.print|System\\.err\\.print|"
					+ "android\\.util\\.Log|println|Timber\\.[a-z]+|Logger\\.[a-z]+");

	/** Log statement pattern. Package-private for testing. */
	static final Pattern LOG_CALL = Pattern.compile(LOG_SINK_PREFIX);

	private static final Pattern LOG_PASSWORD = Pattern.compile(
			"(?:" + LOG_SINK_PREFIX + ").*(?:password|passwd|pwd|secret|credential|pass_phrase)|"
					+ "(?:password|passwd|pwd|secret|credential).*(?:" + LOG_SINK_PREFIX + ")");
	/** Package-private for the framework-sink test. */
	static final Pattern LOG_TOKEN = Pattern.compile(
			"(?:" + LOG_SINK_PREFIX + ").*(?:token|session|auth_token|access_token|refresh_token|jwt|bearer)|"
					+ "(?:token|session|auth_token|access_token).*(?:" + LOG_SINK_PREFIX + ")");
	private static final Pattern LOG_PII = Pattern.compile(
			"(?:" + LOG_SINK_PREFIX + ").*(?:email|phone|ssn|social_security|credit_card|card_number|"
					+ "date_of_birth|address|account_number)");
	/** Package-private for the framework-sink test. */
	static final Pattern LOG_CRYPTO = Pattern.compile(
			"(?:" + LOG_SINK_PREFIX + ").*(?:key|cipher|signature|certificate|keystore|secret_key|private_key)");
	private static final Pattern LOG_AUTH_HEADER = Pattern.compile(
			"(?:" + LOG_SINK_PREFIX + ").*(?:Authorization|Cookie|WWW-Authenticate|Set-Cookie|Bearer)|"
					+ "(?:Authorization|Cookie|Bearer).*(?:" + LOG_SINK_PREFIX + ")");
	private static final Pattern LOG_INTENT_EXTRAS = Pattern.compile(
			"(?:" + LOG_SINK_PREFIX + ").*(?:getIntent\\(\\)|getExtras\\(\\)|Bundle\\.toString|intent\\.getParcelable|getStringExtra)");

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
		new Rule(LOG_PASSWORD, "log_password", "high",
				"Password/credential logged — leaks to Logcat; any app with READ_LOGS "
						+ "can read it; remove or use BuildConfig.DEBUG guard"),
		new Rule(LOG_TOKEN, "log_token", "high",
				"Token/session logged — leaks to Logcat; session hijack risk; "
						+ "remove or use BuildConfig.DEBUG guard"),
		new Rule(LOG_AUTH_HEADER, "log_auth_header", "high",
				"Authorization/Cookie header logged — leaks HTTP credentials to Logcat; "
						+ "session hijack risk; remove or use BuildConfig.DEBUG guard"),
		new Rule(LOG_CRYPTO, "log_crypto_material", "high",
				"Cryptographic material logged — leaks key/cipher material to Logcat; "
						+ "never log crypto material even in debug builds"),
		new Rule(LOG_PII, "log_pii", "medium",
				"PII (email/phone/SSN/card) logged — leaks personally identifiable "
						+ "information to Logcat; privacy violation; remove or redact"),
		new Rule(LOG_INTENT_EXTRAS, "log_intent_extras", "info",
				"Intent extras logged — may leak sensitive data passed between components; "
						+ "review logged content for sensitive values"),
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
		boolean hasCredentialLeak = false;
		boolean hasPiiLeak = false;

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
			if (code == null || code.isEmpty() || !LOG_MARKER.matcher(code).find()) {
				continue;
			}

			// Per-line rule detection (first-match-wins, ONE/class per kind)
			TreeSet<String> reportedKinds = new TreeSet<>();
			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				// Must be a log statement
				if (!LOG_CALL.matcher(line).find()) {
					continue;
				}
				for (Rule r : RULES) {
					if (!reportedKinds.contains(r.kind) && r.pattern.matcher(line).find()) {
						findings.add(finding(r.kind, r.severity, fullName, i + 1, r.detail));
						reportedKinds.add(r.kind);
						if ("high".equals(r.severity)) {
							highSeverityCount++;
						}
						if ("log_password".equals(r.kind) || "log_token".equals(r.kind)
								|| "log_auth_header".equals(r.kind) || "log_crypto_material".equals(r.kind)) {
							hasCredentialLeak = true;
						}
						if ("log_pii".equals(r.kind)) {
							hasPiiLeak = true;
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
		data.put("hasCredentialLeak", hasCredentialLeak);
		data.put("hasPiiLeak", hasPiiLeak);
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
		return "log-info-leak-scan";
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
