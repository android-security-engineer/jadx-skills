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
 * Insecure token/session storage scanner — MASVS MSTG-STORAGE-1.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code storage-scan} (generic insecure storage API usage —
 * world-readable files, cleartext SharedPreferences) and {@code secrets-scan}
 * (hardcoded API keys/credentials via regex/entropy). This scanner focuses on
 * <b>authentication token and session storage</b>: where tokens (JWT, OAuth,
 * session cookies, refresh tokens, auth tokens) are stored and whether the
 * storage mechanism is secure.
 *
 * <p>Categories (first-match-wins per line):
 * <ul>
 *   <li>{@code jwt_insecure} — JWT stored in SharedPreferences or plaintext file
 *       (should be in EncryptedSharedPreferences or KeyStore)</li>
 *   <li>{@code oauth_token_insecure} — OAuth access/refresh token stored in
 *       SharedPreferences or file</li>
 *   <li>{@code session_cookie_insecure} — Session cookie/ID stored in
 *       SharedPreferences or file</li>
 *   <li>{@code auth_token_insecure} — Generic auth/token/credential stored in
 *       SharedPreferences or file without encryption</li>
 *   <li>{@code token_in_keystore} — Token stored in KeyStore or
 *       EncryptedSharedPreferences (defence inventory, not a vulnerability)</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, tokenStorageLocations, truncated}}.
 */
@Command(name = "token-storage-scan",
		description = "Detect insecure token/session storage (MASVS MSTG-STORAGE-1): JWT/OAuth/session cookies in SharedPreferences/files without encryption. Distinct from storage-scan (generic insecure storage) and secrets-scan (hardcoded credentials)")
public class TokenStorageScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes that touch auth token concepts. */
	private static final Pattern TOKEN_MARKER = Pattern.compile(
			"jwt|token|auth_token|access_token|refresh_token|session|cookie|credential|"
					+ "SharedPreferences|EncryptedSharedPreferences|KeyStore|KeyPairGeneratorSpec|"
					+ "KeyGenParameterSpec");

	// Token type indicators in code
	private static final Pattern JWT = Pattern.compile("(?i)jwt|jws|jwe|json\\.?web");
	private static final Pattern OAUTH = Pattern.compile(
			"(?i)access.?token|refresh.?token|oauth|bearer|id_token");
	private static final Pattern SESSION = Pattern.compile(
			"(?i)session.?id|session.?token|cookie|phpsessid|jsessionid|csrf|xsrf");
	private static final Pattern AUTH_TOKEN = Pattern.compile(
			"(?i)auth.?token|auth.?code|credential|login.?token|sign.?in.?token|api.?key");

	// Insecure storage indicators
	private static final Pattern SHARED_PREFS = Pattern.compile(
			"getSharedPreferences|SharedPreferences|putString|getString|edit\\s*\\(\\s*\\)|commit\\s*\\(");
	private static final Pattern PLAIN_FILE = Pattern.compile(
			"openFileOutput|FileOutputStream|writeText|writeBytes|FileWriter|BufferedWriter");
	private static final Pattern DATABASE = Pattern.compile(
			"SQLiteDatabase|execSQL|insert|rawQuery|openOrCreateDatabase");

	// Secure storage indicators
	private static final Pattern ENCRYPTED_PREFS = Pattern.compile(
			"EncryptedSharedPreferences|MasterKey|MasterKeys");
	private static final Pattern KEYSTORE = Pattern.compile(
			"KeyStore\\.getInstance|KeyStore\\.setEntry|KeyStore\\.getEntry|AndroidKeyStore");

	private static final class Rule {
		final Pattern tokenPattern;
		final String kind;
		final String severity;
		final String detail;
		Rule(Pattern tokenPattern, String kind, String severity, String detail) {
			this.tokenPattern = tokenPattern;
			this.kind = kind;
			this.severity = severity;
			this.detail = detail;
		}
	}

	private static final Rule[] RULES = {
		new Rule(JWT, "jwt_insecure", "high",
				"JWT stored in insecure storage (SharedPreferences/file) — JWTs should be stored in "
						+ "EncryptedSharedPreferences or Android KeyStore; otherwise any app with root or "
						+ "backup access can steal the token"),
		new Rule(OAUTH, "oauth_token_insecure", "high",
				"OAuth token stored in insecure storage (SharedPreferences/file) — access/refresh tokens "
						+ "should be stored in EncryptedSharedPreferences or Android KeyStore to prevent "
						+ "credential theft"),
		new Rule(SESSION, "session_cookie_insecure", "high",
				"Session cookie/ID stored in insecure storage (SharedPreferences/file) — session tokens "
						+ "should be stored in EncryptedSharedPreferences to prevent session hijacking"),
		new Rule(AUTH_TOKEN, "auth_token_insecure", "medium",
				"Authentication token/credential stored in insecure storage (SharedPreferences/file) — "
						+ "consider using EncryptedSharedPreferences or Android KeyStore"),
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
		TreeSet<String> tokenStorageLocations = new TreeSet<>();

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
			if (code == null || code.isEmpty() || !TOKEN_MARKER.matcher(code).find()) {
				continue;
			}

			// Determine storage mechanism for this class
			boolean usesSharedPrefs = SHARED_PREFS.matcher(code).find();
			boolean usesPlainFile = PLAIN_FILE.matcher(code).find();
			boolean usesDatabase = DATABASE.matcher(code).find();
			boolean usesEncryptedPrefs = ENCRYPTED_PREFS.matcher(code).find();
			boolean usesKeyStore = KEYSTORE.matcher(code).find();

			// If secure storage is used, report defence inventory
			if (usesEncryptedPrefs || usesKeyStore) {
				boolean reportedSecure = false;
				String[] lines = code.split("\n", -1);
				for (int i = 0; i < lines.length && findings.size() < limit; i++) {
					if (!reportedSecure && (ENCRYPTED_PREFS.matcher(lines[i]).find()
							|| KEYSTORE.matcher(lines[i]).find())) {
						String loc = usesEncryptedPrefs ? "EncryptedSharedPreferences" : "AndroidKeyStore";
						tokenStorageLocations.add(fullName + ":" + loc);
						findings.add(finding("token_in_keystore", "info", fullName, i + 1,
								"Token stored in " + loc + " — secure storage defence present"));
						reportedSecure = true;
					}
				}
				continue; // Secure storage — skip insecure checks for this class
			}

			// Check for insecure token storage
			if (!usesSharedPrefs && !usesPlainFile && !usesDatabase) {
				continue; // No storage mechanism found in this class
			}

			// Per-line detection
			TreeSet<String> reportedKinds = new TreeSet<>();
			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				// Check if this line involves both token AND storage
				boolean lineHasStorage = SHARED_PREFS.matcher(line).find()
						|| PLAIN_FILE.matcher(line).find()
						|| DATABASE.matcher(line).find();
				if (!lineHasStorage) {
					continue;
				}

				for (Rule r : RULES) {
					if (!reportedKinds.contains(r.kind) && r.tokenPattern.matcher(line).find()) {
						String storageType = SHARED_PREFS.matcher(line).find() ? "SharedPreferences"
								: (PLAIN_FILE.matcher(line).find() ? "file" : "database");
						tokenStorageLocations.add(fullName + ":" + storageType);
						findings.add(finding(r.kind, r.severity, fullName, i + 1,
								r.detail + " (found in " + storageType + " operation)"));
						reportedKinds.add(r.kind);
						if ("high".equals(r.severity)) {
							highSeverityCount++;
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
		data.put("tokenStorageLocations", new ArrayList<>(tokenStorageLocations));
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
		return "token-storage-scan";
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
