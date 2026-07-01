package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Scans for account & sync-manageragement surface. {@link android.accounts.AccountManager} is a
 * privileged bridge to the user's online accounts: {@code getAccounts / getAccountsByType}
 * enumerates registered accounts (privacy — what services the user is signed into),
 * {@code peekAuthToken / setAuthToken / addAccountExplicitly} touches auth tokens directly
 * (credential theft / injection), and a custom {@code Authenticator} ({@code
 * AbstractAccountAuthenticator}) lets the app register its own account type — often used to
 * store credentials. Also covers {@code ContentResolver} periodic sync
 * ({@code requestSync / addPeriodicSync}) as a keep-alive/back-channel. MASVS MSTG-STORAGE /
 * MSTG-PRIVACY. Distinct from {@code storage-scan} (files/prefs) and {@code token-storage-scan}
 * (JWT/OAuth in app storage) — this is the system AccountManager credential store.
 *
 * <p>Returns {@code {findings, count, highSeverityCount, usesAccountManager, readsAccounts,
 * touchesAuthTokens, hasAuthenticator, usesSync}}.
 */
@Command(name = "account-scan",
		description = "Scan for AccountManager account enumeration / auth-token access / Authenticator / ContentResolver sync")
public class AccountScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/**
	 * Gate: only scan classes that touch the account/sync surface. Kept in sync with the RULES set —
	 * every rule anchor must appear here or a class exercising only that rule is skipped at the gate
	 * and the finding is silently dropped. {@code addPeriodicSync}/{@code setSyncAutomatically} are
	 * {@code ContentResolver} static methods usable with NO {@code AccountManager} and NO
	 * {@code requestSync} in the class, so a pure periodic-sync class was skipped and
	 * {@code acct_sync} never fired; same for {@code addAccountExplicitly}/{@code invalidateAuthToken}/
	 * {@code getAuthToken}. Package-private so a test can assert the gate covers every rule anchor.
	 */
	static final Pattern ACCT_MARKER = Pattern.compile(
			"AccountManager|AbstractAccountAuthenticator|AccountAuthenticatorActivity|"
					+ "ContentResolver\\.requestSync|addPeriodicSync|setSyncAutomatically|"
					+ "getAccounts|peekAuthToken|setAuthToken|invalidateAuthToken|"
					+ "addAccountExplicitly|getAuthToken|blockingGetAuthToken|AccountAuthenticator");

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
			new Rule("peekAuthToken\\s*\\(|setAuthToken\\s*\\(|invalidateAuthToken\\s*\\(",
					"acct_auth_token", "high",
					"AccountManager peekAuthToken / setAuthToken / invalidateAuthToken — reads, sets, or clears auth tokens directly; credential access bypassing the normal auth flow"),
			new Rule("addAccountExplicitly\\s*\\(",
					"acct_add_account", "medium",
					"AccountManager.addAccountExplicitly — registers a new account (and its initial credentials) into the system store; review what credential material is stored"),
			new Rule("getAccounts\\s*\\(|getAccountsByType\\s*\\(",
					"acct_enumerate", "high",
					"AccountManager.getAccounts / getAccountsByType — enumerates the user's registered accounts (which services they use); privacy-sensitive, needs GET_ACCOUNTS"),
			new Rule("extends\\s+AbstractAccountAuthenticator|AccountAuthenticatorActivity",
					"acct_authenticator", "medium",
					"Implements an AccountAuthenticator — registers a custom account type; the Authenticator is the credential store for that account, a credential-theft target"),
			new Rule("blockingGetAuthToken\\s*\\(|getAuthToken\\s*\\(",
					"acct_get_token", "medium",
					"AccountManager.getAuthToken / blockingGetAuthToken — fetches an auth token for an account; legitimate but the token is a bearer credential"),
			new Rule("ContentResolver\\.requestSync\\s*\\(|addPeriodicSync\\s*\\(|setSyncAutomatically\\s*\\(",
					"acct_sync", "low",
					"ContentResolver requestSync / addPeriodicSync — triggers or schedules a sync (background data exchange with the account's service); a keep-alive / back-channel surface"));

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
		boolean usesAccountManager = false;
		boolean readsAccounts = false;
		boolean touchesAuthTokens = false;
		boolean hasAuthenticator = false;
		boolean usesSync = false;

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
			if (code == null || code.isEmpty() || !ACCT_MARKER.matcher(code).find()) {
				continue;
			}
			usesAccountManager = true;

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!r.pattern.matcher(line).find()) {
						continue;
					}
					findings.add(finding(fullName, i + 1, r.kind, r.severity, r.detail));
					if ("high".equals(r.severity)) {
						highSeverityCount++;
					}
					if ("acct_enumerate".equals(r.kind)) {
						readsAccounts = true;
					}
					if ("acct_auth_token".equals(r.kind)) {
						touchesAuthTokens = true;
					}
					if ("acct_authenticator".equals(r.kind)) {
						hasAuthenticator = true;
					}
					if ("acct_sync".equals(r.kind)) {
						usesSync = true;
					}
					break;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("usesAccountManager", usesAccountManager);
		data.put("readsAccounts", readsAccounts);
		data.put("touchesAuthTokens", touchesAuthTokens);
		data.put("hasAuthenticator", hasAuthenticator);
		data.put("usesSync", usesSync);
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
		return "account-scan";
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
