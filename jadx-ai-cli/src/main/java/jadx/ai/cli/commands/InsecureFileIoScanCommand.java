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
 * Insecure file I/O scanner — MASVS MSTG-STORAGE.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects insecure file operations: world-readable/writable files,
 * unencrypted sensitive data written to internal storage, temp file
 * race conditions, and file operations on external storage without
 * encryption. Distinct from {@code storage-scan} (generic insecure
 * storage patterns) and {@code data-residue-scan} (data surviving
 * uninstall) — this scanner focuses on <b>file I/O API misuse</b>.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code world_readable_file} — MODE_WORLD_READABLE /
 *       openFileOutput with world-readable flag — any app can read</li>
 *   <li>{@code world_writable_file} — MODE_WORLD_WRITEABLE /
 *       openFileOutput with world-writable flag — any app can modify</li>
 *   <li>{@code sensitive_file_unencrypted} — Password/token/PII written to
 *       file without encryption — extractable from device backup or root</li>
 *   <li>{@code temp_file_race} — File.createTempFile without secure
 *       delete — TOCTOU race condition; use FileProvider instead</li>
 *   <li>{@code file_provider_misconfig} — FileProvider with overly broad
 *       path grant (external-files-path root, /) — exposes all files</li>
 *   <li>{@code internal_file_io} — File I/O on internal storage —
 *       positive indicator; internal storage is app-private by default</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasWorldReadable, hasUnencryptedSensitive, truncated}}.
 */
@Command(name = "insecure-file-io-scan",
		description = "Detect insecure file I/O (MASVS MSTG-STORAGE): world-readable/writable files, sensitive data written unencrypted, temp file races, FileProvider misconfiguration. Distinct from storage-scan and data-residue-scan")
public class InsecureFileIoScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with file I/O markers. */
	private static final Pattern FILE_MARKER = Pattern.compile(
			"FileOutputStream|FileInputStream|openFileOutput|openFileInput|"
					+ "MODE_WORLD|createTempFile|FileProvider|"
					+ "writeFile|writeBytes|BufferedWriter|FileWriter|"
					+ "getFilesDir|getCacheDir|getDir");

	private static final Pattern WORLD_READABLE = Pattern.compile(
			"MODE_WORLD_READABLE|openFileOutput.*MODE_WORLD_READABLE|"
					+ "setReadable\\s*\\(\\s*true\\s*,\\s*false|"
					+ "chmod\\s+644|chmod\\s+664|"
					+ "MODE_WORLD_READABLE.*openFileOutput");
	private static final Pattern WORLD_WRITABLE = Pattern.compile(
			"MODE_WORLD_WRITEABLE|openFileOutput.*MODE_WORLD_WRITEABLE|"
					+ "setWritable\\s*\\(\\s*true\\s*,\\s*false|"
					+ "chmod\\s+666|chmod\\s+646");
	private static final Pattern SENSITIVE_UNENCRYPTED = Pattern.compile(
			"FileOutputStream.*(?:password|token|secret|key|credential|auth|session)|"
					+ "openFileOutput.*(?:password|token|secret|key|credential)|"
					+ "writeBytes.*(?:password|token|secret)|"
					+ "FileWriter.*(?:password|token|secret|key)|"
					+ "BufferedWriter.*(?:password|token|secret)");
	private static final Pattern TEMP_FILE = Pattern.compile(
			"createTempFile|File\\.createTempFile|"
					+ "tempFile|tmpFile|TEMP_FILE");
	private static final Pattern FILE_PROVIDER = Pattern.compile(
			"FileProvider|getUriForFile|"
					+ "external-files-path|external-path|"
					+ "external-cache-path|files-path|cache-path|"
					+ "grantUriPermission");
	private static final Pattern INTERNAL_FILE = Pattern.compile(
			"getFilesDir|getCacheDir|getDir\\s*\\(|"
					+ "openFileOutput\\s*\\(\\s*\"|"
					+ "openFileInput\\s*\\(\\s*\"");

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
		new Rule(WORLD_READABLE, "world_readable_file", "high",
				"MODE_WORLD_READABLE — any app can read this file; deprecated since "
						+ "API 17; use internal storage or ContentProvider with permission"),
		new Rule(WORLD_WRITABLE, "world_writable_file", "high",
				"MODE_WORLD_WRITEABLE — any app can modify this file; deprecated since "
						+ "API 17; use ContentProvider with permission for data sharing"),
		new Rule(SENSITIVE_UNENCRYPTED, "sensitive_file_unencrypted", "high",
				"Sensitive data (password/token/key) written to file without encryption — "
						+ "extractable from device backup or root; use EncryptedFile or "
						+ "Android Keystore"),
		new Rule(TEMP_FILE, "temp_file_race", "medium",
				"Temp file created — TOCTOU race condition and cleanup issues; "
						+ "use FileProvider or internal cache with secure delete"),
		new Rule(FILE_PROVIDER, "file_provider_misconfig", "info",
				"FileProvider usage — verify path configuration is not overly broad; "
						+ "avoid sharing root or external storage paths"),
		new Rule(INTERNAL_FILE, "internal_file_io", "info",
				"Internal file I/O — positive indicator; internal storage is "
						+ "app-private by default"),
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
		boolean hasWorldReadable = false;
		boolean hasUnencryptedSensitive = false;

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
			if (code == null || code.isEmpty() || !FILE_MARKER.matcher(code).find()) {
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
						if ("world_readable_file".equals(r.kind) || "world_writable_file".equals(r.kind)) {
							hasWorldReadable = true;
						}
						if ("sensitive_file_unencrypted".equals(r.kind)) {
							hasUnencryptedSensitive = true;
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
		data.put("hasWorldReadable", hasWorldReadable);
		data.put("hasUnencryptedSensitive", hasUnencryptedSensitive);
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
		return "insecure-file-io-scan";
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
