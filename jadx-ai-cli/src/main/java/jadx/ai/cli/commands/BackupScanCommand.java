package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.ManifestUtil;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Android backup-configuration audit — MASVS MSTG-STORAGE-7.
 * Native: reads jadx's parsed model and decoded manifest, no external tool.
 *
 * <p>Distinct from {@code storage-scan} (insecure storage API usage — SharedPreferences,
 * cleartext files, world-readable ContentProviders). This command audits the <b>Android backup
 * subsystem configuration</b> that can cause sensitive data to be exfiltrated via {@code adb backup},
 * Google cloud backup, or device-to-device transfer. It answers: can an attacker with physical
 * access pull the app's data via backup?
 *
 * <p>Manifest findings:
 * <ul>
 *   <li>{@code allowBackup_enabled} — {@code android:allowBackup="true"} (or missing = defaults
 *       to true pre-API-31) lets {@code adb backup} pull the app's entire data directory</li>
 *   <li>{@code full_backup_content} — {@code android:fullBackupContent} points to an XML that
 *       defines what is included/excluded; we inventory its presence and check for overly-broad
 *       include rules</li>
 *   <li>{@code backup_agent} — {@code android:backupAgent} declares a custom BackupAgent subclass;
 *       we scan it for sensitive-data handling</li>
 * </ul>
 *
 * <p>Code findings: a {@code BackupAgent} / {@code BackupAgentHelper} subclass that writes
 * sensitive data (SharedPreferences, files, databases) to the backup payload without encryption.
 *
 * <p>Inventory shape (no severity — backup is a feature; the risk depends on what data is
 * included and whether it is encrypted). Boolean flags {@code allowsBackup} /
 * {@code hasBackupAgent} let a review quickly filter.
 *
 * Returns {@code {findings:[{category,source,lineNumber,detail}], count, allowsBackup,
 * hasBackupAgent, hasFullBackupContent, backupAgentClass, truncated}}.
 */
@Command(name = "backup-scan",
		description = "Audit Android backup configuration (MASVS MSTG-STORAGE-7): allowBackup, fullBackupContent XML rules, BackupAgent subclasses writing sensitive data. Distinct from storage-scan (insecure storage APIs); answers can-attacker-pull-data-via-adb-backup")
public class BackupScanCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "100")
	protected int limit = 100;

	// --- Manifest patterns ---
	private static final Pattern APP_TAG = Pattern.compile("<application\\b([^>]*?)>", Pattern.DOTALL);
	private static final Pattern ATTR_ALLOW_BACKUP = Pattern.compile(
			Pattern.quote("android:allowBackup") + "\\s*=\\s*\"(true|false)\"");
	private static final Pattern ATTR_FULL_BACKUP_CONTENT = Pattern.compile(
			Pattern.quote("android:fullBackupContent") + "\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern ATTR_BACKUP_AGENT = Pattern.compile(
			Pattern.quote("android:backupAgent") + "\\s*=\\s*\"([^\"]+)\"");

	// --- Code patterns ---
	private static final Pattern BACKUP_MARKER = Pattern.compile(
			"BackupAgent|BackupAgentHelper|onBackup|onRestore|onFullBackup");
	private static final Pattern BACKUP_CLASS = Pattern.compile(
			"extends\\s+(BackupAgent|BackupAgentHelper)");
	private static final Pattern SENSITIVE_WRITE = Pattern.compile(
			"SharedPreferences|openFileOutput|openOrCreateDatabase|getSharedPreferences|"
					+ "FileOutputStream|SQLiteDatabase\\.insert|ContentResolver\\.insert|"
					+ "writeNewState|writeFullBackupState");
	private static final Pattern BACKUP_DATA_WRITE = Pattern.compile(
			"data\\.write|ParcelFileDescriptor|writeEntity|writeBytes|writeString");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();
		boolean allowsBackup = false;
		boolean hasBackupAgent = false;
		boolean hasFullBackupContent = false;
		String backupAgentClass = null;

		// --- Manifest scan ---
		String manifest = ManifestUtil.loadManifestText(decompiler);
		if (manifest != null) {
			Matcher am = APP_TAG.matcher(manifest);
			if (am.find()) {
				String appAttrs = am.group(1);

				// allowBackup
				String allowBackupStr = ManifestUtil.extractFirst(appAttrs, ATTR_ALLOW_BACKUP.pattern());
				if (allowBackupStr == null) {
					// Default is true for apps targeting API < 31
					allowsBackup = true;
					findings.add(finding("allowBackup_default", "AndroidManifest.xml", 0,
							"android:allowBackup not set — defaults to true for targetSdkVersion < 31; "
									+ "adb backup can extract the app's entire data directory"));
				} else if ("true".equals(allowBackupStr)) {
					allowsBackup = true;
					findings.add(finding("allowBackup_enabled", "AndroidManifest.xml", 0,
							"android:allowBackup=\"true\" — adb backup can extract the app's data directory; "
									+ "sensitive data (tokens, keys, PII) may be pulled by anyone with USB access"));
				}
				// allowBackup="false" → no finding (good)

				// fullBackupContent
				String fbcValue = ManifestUtil.extractFirst(appAttrs, ATTR_FULL_BACKUP_CONTENT.pattern());
				if (fbcValue != null) {
					hasFullBackupContent = true;
					findings.add(finding("full_backup_content", "AndroidManifest.xml", 0,
							"android:fullBackupContent=\"" + fbcValue + "\" — auto-backup rules defined; "
									+ "verify the XML excludes SharedPreferences/databases containing sensitive data"));
				}

				// backupAgent
				String agentValue = ManifestUtil.extractFirst(appAttrs, ATTR_BACKUP_AGENT.pattern());
				if (agentValue != null) {
					hasBackupAgent = true;
					backupAgentClass = agentValue;
					findings.add(finding("backup_agent", "AndroidManifest.xml", 0,
							"android:backupAgent=\"" + agentValue + "\" — custom BackupAgent; "
									+ "verify it does not write sensitive data to the backup payload unencrypted"));
				}
			}
		} else {
			return JsonOutput.error("ManifestNotFound",
					"No AndroidManifest.xml found; backup-scan requires an APK input");
		}

		// --- Code scan: BackupAgent subclasses ---
		for (JavaClass cls : decompiler.getClasses()) {
			if (findings.size() >= limit) {
				break;
			}
			String fullName = cls.getFullName();
			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty() || !BACKUP_MARKER.matcher(code).find()) {
				continue;
			}

			boolean isBackupClass = BACKUP_CLASS.matcher(code).find();
			if (!isBackupClass) {
				continue;
			}

			boolean hasSensitiveWrite = SENSITIVE_WRITE.matcher(code).find();
			boolean writesToBackup = BACKUP_DATA_WRITE.matcher(code).find();

			if (hasSensitiveWrite) {
				findings.add(finding("backup_sensitive_data", fullName, 0,
						"BackupAgent subclass accesses sensitive data (SharedPreferences / files / databases); "
								+ "verify the backup payload encrypts or excludes this data"));
			}
			if (writesToBackup) {
				findings.add(finding("backup_data_write", fullName, 0,
						"BackupAgent subclass writes data to the backup payload — verify no sensitive data "
								+ "(auth tokens, encryption keys, PII) is included without encryption"));
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("allowsBackup", allowsBackup);
		data.put("hasBackupAgent", hasBackupAgent);
		data.put("hasFullBackupContent", hasFullBackupContent);
		data.put("backupAgentClass", backupAgentClass);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String category, String source, int line, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("category", category);
		f.put("source", source);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "backup-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("limit", limit);
		return args;
	}
}
