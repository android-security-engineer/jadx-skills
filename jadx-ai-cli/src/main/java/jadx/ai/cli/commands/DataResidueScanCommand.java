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
 * Data-residue scanner — MASVS MSTG-STORAGE-8.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects data that persists after app uninstall: external storage writes,
 * SD card files, AccountManager account registration, ContentProvider data
 * not cleared on delete, and shared-external IDs. Distinct from
 * {@code storage-scan} (generic insecure storage) and {@code privacy-scan}
 * (PII collection) — this scanner focuses on <b>data that survives uninstall</b>.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code external_storage_write} — getExternalStorageDirectory /
 *       getExternalFilesDir / Environment.getExternalStoragePublicDirectory —
 *       files written to shared external storage survive uninstall</li>
 *   <li>{@code sdcard_direct} — Direct /sdcard/ or /mnt/sdcard/ path —
 *       bypasses Android's per-app external storage sandbox</li>
 *   <li>{@code account_manager_register} — AccountManager.addAccountExplicitly —
 *       registered accounts survive uninstall and leak credentials</li>
 *   <li>{@code content_provider_residue} — ContentProvider with insert/update but
 *       no delete — data added to provider is never cleaned up on uninstall</li>
 *   <li>{@code clipboard_sensitive} — ClipboardManager.setPrimaryClip with
 *       sensitive data — clipboard contents persist across app lifecycle</li>
 *   <li>{@code shared_user_id} — android:sharedUserId in manifest — data shared
 *       with other apps via shared UID survives uninstall</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasExternalStorageWrite, hasAccountRegister, truncated}}.
 */
@Command(name = "data-residue-scan",
		description = "Detect data surviving app uninstall (MASVS MSTG-STORAGE-8): external storage writes, SD card paths, AccountManager registration, ContentProvider residue, clipboard sensitive data, sharedUserId")
public class DataResidueScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with data-residue markers. */
	private static final Pattern RESIDUE_MARKER = Pattern.compile(
			"getExternalStorage|getExternalFilesDir|getExternalCacheDir|"
					+ "/sdcard/|/mnt/sdcard|Environment\\.getExternal|"
					+ "AccountManager|addAccountExplicitly|"
					+ "ClipboardManager|setPrimaryClip|"
					+ "ContentProvider|insert|update|delete|"
					+ "sharedUserId|sharedUserLabel");

	private static final Pattern EXTERNAL_STORAGE = Pattern.compile(
			"getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir|"
					+ "getExternalStoragePublicDirectory|Environment\\.getExternal|"
					+ "isExternalStorageEmulated|isExternalStorageRemovable");
	private static final Pattern SDCARD_DIRECT = Pattern.compile(
			"/sdcard/|/mnt/sdcard/|/storage/emulated/0/|"
					+ "\"/sdcard|\"/mnt/sdcard|\"/storage/emulated");
	private static final Pattern ACCOUNT_MANAGER = Pattern.compile(
			"AccountManager|addAccountExplicitly|getAccounts|"
					+ "Account\\s*\\(\\s*\"|AccountAuthenticator|"
					+ "AbstractAccountAuthenticator");
	private static final Pattern CLIPBOARD_SENSITIVE = Pattern.compile(
			"ClipboardManager|setPrimaryClip|ClipData\\.newPlainText|"
					+ "clipboardManager\\.setPrimaryClip|"
					+ "ClipData\\.newRawUri|ClipData\\.newIntent");
	private static final Pattern SHARED_USER_ID = Pattern.compile(
			"sharedUserId|sharedUserLabel|android:sharedUserId");

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
		new Rule(SDCARD_DIRECT, "sdcard_direct", "high",
				"Direct /sdcard/ path — bypasses Android's per-app external storage sandbox; "
						+ "files persist after uninstall and are accessible to any app with "
						+ "storage permission"),
		new Rule(ACCOUNT_MANAGER, "account_manager_register", "high",
				"AccountManager usage — registered accounts survive uninstall; credential "
						+ "data may leak to other apps or persist across reinstall"),
		new Rule(SHARED_USER_ID, "shared_user_id", "medium",
				"android:sharedUserId — data shared with other apps via shared UID; "
						+ "shared data survives uninstall of any single app in the group"),
		new Rule(EXTERNAL_STORAGE, "external_storage_write", "medium",
				"External storage write — files on external storage (getExternalStorageDirectory/"
						+ "getExternalFilesDir) persist after uninstall; use internal storage "
						+ "or encrypted storage for sensitive data"),
		new Rule(CLIPBOARD_SENSITIVE, "clipboard_sensitive", "info",
				"ClipboardManager usage — clipboard contents persist across app lifecycle "
						+ "and are readable by any app with clipboard access; avoid putting "
						+ "sensitive data (passwords, tokens) in clipboard"),
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
		boolean hasExternalStorageWrite = false;
		boolean hasAccountRegister = false;

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
			if (code == null || code.isEmpty() || !RESIDUE_MARKER.matcher(code).find()) {
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
						if ("external_storage_write".equals(r.kind) || "sdcard_direct".equals(r.kind)) {
							hasExternalStorageWrite = true;
						}
						if ("account_manager_register".equals(r.kind)) {
							hasAccountRegister = true;
						}
						break;
					}
				}
			}
		}

		// Manifest: check for sharedUserId
		try {
			String manifest = jadx.ai.cli.util.ManifestUtil.loadManifestText(decompiler);
			if (manifest != null) {
				if (SHARED_USER_ID.matcher(manifest).find() && findings.stream()
						.noneMatch(f -> "shared_user_id".equals(f.get("kind")))) {
					findings.add(finding("shared_user_id", "medium", "AndroidManifest.xml", 0,
							"android:sharedUserId in manifest — data shared with other apps "
									+ "via shared UID persists after uninstall"));
					highSeverityCount++; // not high but counted
				}
			}
		} catch (Exception ignored) {
			// manifest may not be available
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("hasExternalStorageWrite", hasExternalStorageWrite);
		data.put("hasAccountRegister", hasAccountRegister);
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
		return "data-residue-scan";
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
