package jadx.ai.cli.commands;

import java.util.ArrayList;
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
 * Scans decompiled code for insecure local data storage — the MASVS MSTG-STORAGE category, the
 * single most common real-world Android finding and one no other scanner here covers
 * ({@code manifest-audit} flags {@code allowBackup} at the app level, but never the in-code storage
 * sinks). Native capability: reads jadx's parsed model, no external tool.
 *
 * <p>Flags, per source line:
 * <ul>
 *   <li><b>World-accessible files</b> — {@code MODE_WORLD_READABLE}/{@code MODE_WORLD_WRITEABLE}
 *       passed to {@code openFileOutput}/{@code getSharedPreferences}/{@code openOrCreateDatabase}.
 *       Deprecated since API 17 precisely because any other app can read/clobber the data (high).</li>
 *   <li><b>Sensitive data on shared/external storage</b> — {@code getExternalStorageDirectory},
 *       {@code getExternalFilesDir}, {@code getExternalStoragePublicDirectory},
 *       {@code getExternalCacheDir}: world-readable on legacy devices, survives uninstall, not
 *       protected by the app sandbox (medium).</li>
 *   <li><b>Unencrypted SharedPreferences</b> — {@code getSharedPreferences}/{@code PreferenceManager}
 *       without the EncryptedSharedPreferences wrapper (info; downgraded when Jetpack Security is
 *       present in the class).</li>
 *   <li><b>Unencrypted SQLite</b> — {@code openOrCreateDatabase}/{@code SQLiteOpenHelper}/
 *       {@code SQLiteDatabase} without SQLCipher (info; downgraded when {@code net.sqlcipher} present).</li>
 *   <li><b>Temp files</b> — {@code File.createTempFile} (low; world-readable temp dir on some OEMs).</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, usesEncryptedPrefs,
 * usesSqlCipher, truncated}}. The two booleans tell a reviewer at a glance whether the app even has
 * the secure-storage primitives available — an app with zero EncryptedSharedPreferences usage and a
 * dozen plain {@code getSharedPreferences} calls is a very different risk profile from one that has
 * adopted Jetpack Security everywhere.
 */
@Command(name = "storage-scan",
		description = "Scan code for insecure local data storage (MODE_WORLD_*, external storage, unencrypted SharedPreferences/SQLite)")
public class StorageScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** A single line-level rule: a compiled pattern plus how to report a match. */
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
			new Rule("MODE_WORLD_READABLE", "world_readable", "high",
					"MODE_WORLD_READABLE — any app on the device can read this file/prefs/db"),
			new Rule("MODE_WORLD_WRITEABLE|MODE_WORLD_WRITABLE", "world_writable", "high",
					"MODE_WORLD_WRITEABLE — any app on the device can overwrite this file/prefs/db"),
			new Rule("getExternalStorageDirectory\\(", "external_storage", "medium",
					"Writes to shared external storage (world-readable on legacy, survives uninstall, outside sandbox)"),
			new Rule("getExternalStoragePublicDirectory\\(", "external_storage", "medium",
					"Writes to public external storage directory (shared, not sandbox-protected)"),
			new Rule("getExternalFilesDir\\(", "external_storage", "low",
					"App-specific external storage — not sandbox-protected; avoid for sensitive data"),
			new Rule("getExternalCacheDir\\(", "external_storage", "low",
					"External cache dir — shared storage; do not cache sensitive data here"),
			new Rule("getSharedPreferences\\(|PreferenceManager\\.getDefaultSharedPreferences\\(", "plaintext_prefs", "info",
					"SharedPreferences stored in plaintext — prefer EncryptedSharedPreferences for sensitive data"),
			new Rule("openOrCreateDatabase\\(|extends\\s+SQLiteOpenHelper|SQLiteDatabase\\.openDatabase\\(", "plaintext_db", "info",
					"Unencrypted SQLite database — prefer SQLCipher for sensitive data"),
			new Rule("File\\.createTempFile\\(", "temp_file", "low",
					"Temp file created — verify it holds no sensitive data and is deleted"));

	/** Presence of these in a class means the secure alternative is in play; downgrade noise. */
	private static final Pattern ENCRYPTED_PREFS_MARKER =
			Pattern.compile("EncryptedSharedPreferences|androidx\\.security\\.crypto|MasterKey");
	private static final Pattern SQLCIPHER_MARKER =
			Pattern.compile("net\\.sqlcipher|SQLiteDatabase\\.loadLibs|net/sqlcipher");

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
		boolean usesEncryptedPrefs = false;
		boolean usesSqlCipher = false;

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

			boolean classHasEncPrefs = ENCRYPTED_PREFS_MARKER.matcher(code).find();
			boolean classHasSqlCipher = SQLCIPHER_MARKER.matcher(code).find();
			usesEncryptedPrefs |= classHasEncPrefs;
			usesSqlCipher |= classHasSqlCipher;

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;
				for (Rule rule : RULES) {
					if (!rule.pattern.matcher(line).find()) {
						continue;
					}
					// Suppress the "plaintext" info findings when the class clearly uses the
					// encrypted/SQLCipher alternative — the match is almost certainly the secure path.
					if ("plaintext_prefs".equals(rule.kind) && classHasEncPrefs) {
						continue;
					}
					if ("plaintext_db".equals(rule.kind) && classHasSqlCipher) {
						continue;
					}
					findings.add(finding(fullName, ln, rule.kind, rule.severity, rule.detail));
					if (findings.size() >= limit) {
						break;
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("usesEncryptedPrefs", usesEncryptedPrefs);
		data.put("usesSqlCipher", usesSqlCipher);
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
		return "storage-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new java.util.HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
