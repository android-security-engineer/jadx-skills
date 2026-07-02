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
 * Trust-boundary violation scanner — MASVS MSTG-PLATFORM/AUTH.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects data from untrusted sources (Intent extras, Bundle, SharedPreferences
 * without integrity check) used directly for security decisions (authentication,
 * authorization, permission checks) without validation.
 *
 * <p>Distinct from {@code intent-redirection-scan} (intent forwarding to components),
 * {@code intent-scan} (generic intent misuse), and {@code local-auth-bypass-scan}
 * (auth method logic flaws) — this scanner focuses on <b>trust boundary
 * violations where untrusted input drives security decisions</b>.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code intent_auth_decision} — getIntent().getBooleanExtra("isAdmin") etc.
 *       used for authorization — attacker can set extras to elevate privileges</li>
 *   <li>{@code shared_prefs_auth} — SharedPreferences.getBoolean("isLoggedIn") etc.
 *       used for auth state — modifiable by root, not a secure auth store</li>
 *   <li>{@code bundle_role_check} — Bundle extra used for role/permission check —
 *       Bundle from Intent can be forged by any sender</li>
 *   <li>{@code unvalidated_intent_action} — Action from received Intent used for
 *       branching without validation — attacker can set any action string</li>
 *   <li>{@code external_data_sql} — Intent/Bundle data used in SQL —
 *       SQL injection via untrusted input; detected across lines (class-scope
 *       IPC source on one line flows into a SQL sink on another), because jadx
 *       decompiles source extraction and the sink separately</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasAuthDecisionFromIntent, truncated}}.
 */
@Command(name = "trust-boundary-scan",
		description = "Detect trust boundary violations (MASVS MSTG-PLATFORM/AUTH): Intent extras for auth/role decisions, SharedPreferences for auth state, unvalidated intent actions, Bundle role checks. Distinct from intent-redirection/intent-scan/local-auth-bypass")
public class TrustBoundaryScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with intent/auth markers. */
	private static final Pattern TRUST_MARKER = Pattern.compile(
			"getIntent|getStringExtra|getBooleanExtra|getIntExtra|getBundleExtra|"
					+ "SharedPreferences|getSharedPreferences|isLoggedIn|isAuthenticated|"
					+ "isAdmin|isRoot|hasPermission|ACTION_|getAction");

	/**
	 * An Intent extra used as an auth/privilege decision — e.g. {@code getIntent().getBooleanExtra("isAdmin", false)}
	 * then branching on it (the extra is attacker-controlled via a crafted Intent). Was a FALSE-POSITIVE
	 * AMPLIFIER: {@code getIntent.*role}/{@code getBooleanExtra.*login}/etc. paired the getter with any
	 * same-line substring, so a log line ({@code Log.d("intent=" + getIntent() + " role=" + getRole())})
	 * was flagged {@code intent_auth_decision} <b>high</b>. Now the sensitive keyword must appear inside
	 * the extra-NAME string literal of a {@code getXxxExtra("...")} call (the actual attacker-controlled
	 * channel), not as an arbitrary same-line substring. Package-private for testing.
	 */
	static final Pattern INTENT_AUTH = Pattern.compile(
			"getBooleanExtra\\s*\\(\\s*\"(?:isAdmin|isRoot|isAuthenticated|isLoggedIn|admin|root|auth|login|role|permission|privilege|access|auth_level|access_level)\"|"
					+ "getIntExtra\\s*\\(\\s*\"(?:isAdmin|isRoot|isAuthenticated|isLoggedIn|admin|root|auth|role|permission|level|auth_level|access_level|privilege)\"|"
					+ "getStringExtra\\s*\\(\\s*\"(?:isAdmin|isRoot|isAuthenticated|isLoggedIn|role|permission|auth_level|access_level|privilege|admin|auth)\"|"
					+ "getBundleExtra\\s*\\(\\s*\"(?:isAdmin|isRoot|isAuthenticated|isLoggedIn|role|permission|auth_level|access_level|admin|auth|privilege)\"");
	private static final Pattern SHARED_PREFS_AUTH = Pattern.compile(
			"SharedPreferences.*(?:isLoggedIn|isAuthenticated|login|auth|session)|"
					+ "getBoolean.*(?:isLoggedIn|isAuthenticated|loggedIn|authenticated)|"
					+ "getString.*(?:auth_token|session_token|login_state)|"
					+ "getSharedPreferences.*(?:auth|login|session|credential)");
	private static final Pattern BUNDLE_ROLE = Pattern.compile(
			"getBundleExtra.*(?:role|permission|auth|admin)|"
					+ "Bundle.*(?:isAdmin|isRoot|role|permission|auth_level)|"
					+ "bundle\\.getBoolean.*(?:admin|root|auth|role)|"
					+ "bundle\\.getString.*(?:role|permission|auth_level)");
	private static final Pattern UNVALIDATED_ACTION = Pattern.compile(
			"getAction\\s*\\(\\)\\s*\\.equals|getAction.*equalsIgnoreCase|"
					+ "ACTION_.*equals.*getAction|"
					+ "if\\s*\\(.*getAction\\s*\\(\\)|switch\\s*\\(.*getAction");
	/**
	 * IPC-source markers (Intent/Bundle extras) matched at CLASS scope. jadx decompiles the source
	 * extraction and the SQL sink on separate lines ({@code String n = getIntent().getStringExtra("n");}
	 * then {@code db.rawQuery("..." + n, null);}), so the same-line {@code EXTERNAL_DATA_SQL} AND
	 * missed it. Paired with {@link #EXTERNAL_DATA_SQL_SINK} (line-scope) this is the cross-line form.
	 * Package-private for testing.
	 */
	static final Pattern IPC_SOURCE = Pattern.compile(
			"getIntent\\s*\\(\\s*\\)|getStringExtra|getBundleExtra|getBooleanExtra|getIntExtra|"
					+ "Bundle\\s+\\w+\\s*=|getExtras\\s*\\(");

	/**
	 * SQL injection sink reached from an IPC source on another line. Was a FALSE-POSITIVE AMPLIFIER: the
	 * old sink matched {@code .query/.insert/.update/.delete} too — but those are the parameterized
	 * (ContentValues + selectionArgs) APIs that are SAFE by construction; every normal database class
	 * that reads an Intent extra and writes it via {@code db.insert(...)} was flagged
	 * {@code external_data_sql} <b>high</b>. Now restricted to the genuine injection sinks
	 * ({@code rawQuery}/{@code execSQL}/{@code compileStatement}) AND requires a string-literal SQL
	 * concatenated with {@code +} on the same line (the actual injection shape
	 * {@code rawQuery("...'" + extra + "'")}); a parameterized {@code rawQuery("...=?", args)} does not
	 * fire. Verified against real javac&#8594;d8&#8594;jadx output. Package-private for testing.
	 */
	static final Pattern EXTERNAL_DATA_SQL_SINK = Pattern.compile(
			"\\.rawQuery\\s*\\([^)]*\"[^)]*\\+|"
					+ "\\.execSQL\\s*\\([^)]*\"[^)]*\\+|"
					+ "compileStatement\\s*\\([^)]*\"[^)]*\\+");

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
		new Rule(INTENT_AUTH, "intent_auth_decision", "high",
				"Intent extra used for auth/role decision — attacker controls Intent extras; "
						+ "never trust Intent data for authorization; verify against server-side "
						+ "state or signed data"),
		new Rule(SHARED_PREFS_AUTH, "shared_prefs_auth", "medium",
				"SharedPreferences used for auth state — modifiable by root/users; "
						+ "not a secure auth store; use server-side session validation or "
						+ "EncryptedSharedPreferences with server-verified tokens"),
		new Rule(BUNDLE_ROLE, "bundle_role_check", "medium",
				"Bundle extra used for role/permission check — Bundle from Intent can be "
						+ "forged by any sender; validate against server-side state"),
		new Rule(UNVALIDATED_ACTION, "unvalidated_intent_action", "info",
				"Intent action used for branching — ensure all action strings are validated "
						+ "against a whitelist; an attacker can set any action string"),
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
		boolean hasAuthDecisionFromIntent = false;

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
			if (code == null || code.isEmpty() || !TRUST_MARKER.matcher(code).find()) {
				continue;
			}

			// Per-line rule detection (first-match-wins, ONE/class per kind)
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
						if ("intent_auth_decision".equals(r.kind) || "bundle_role_check".equals(r.kind)) {
							hasAuthDecisionFromIntent = true;
						}
						break;
					}
				}
			}

			// Cross-line IPC→SQL: jadx decompiles the source extraction and the SQL sink on separate
			// lines (String n = getIntent().getStringExtra("n"); db.rawQuery("..." + n, null);), so the
			// same-line EXTERNAL_DATA_SQL AND missed the common form. Class-scope IPC_SOURCE ∧ line-scope
			// SQL sink (lineNumber = first sink line). ONE/class. Mirrors ExportedProviderScan/PathTraversal.
			if (findings.size() < limit
					&& !reportedKinds.contains("external_data_sql")
					&& IPC_SOURCE.matcher(code).find()) {
				for (int i = 0; i < lines.length; i++) {
					if (EXTERNAL_DATA_SQL_SINK.matcher(lines[i]).find()) {
						findings.add(finding("external_data_sql", "high", fullName, i + 1,
								"Intent/Bundle data used in SQL — SQL injection via untrusted IPC input; "
										+ "use parameterized queries (selectionArgs) instead of string "
										+ "concatenation; never feed Intent extras into a SQL sink"));
						highSeverityCount++;
						break;
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("hasAuthDecisionFromIntent", hasAuthDecisionFromIntent);
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
		return "trust-boundary-scan";
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
