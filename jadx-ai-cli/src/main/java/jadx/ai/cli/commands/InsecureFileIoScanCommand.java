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
import jadx.api.ResourceFile;
import jadx.api.ResourceType;

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
 *   <li>{@code file_provider_misconfig} — FileProvider usage in code (info, verify path config) OR
 *       a {@code res/xml/*paths*.xml} declaring an overly-broad path ({@code <root-path>}, external
 *       path with {@code path="/"} or {@code ""}, or {@code grant-all-permissions}) — the latter is
 *       high severity: any URI holder reads the filesystem root / external storage (CWE-22/CWE-732)</li>
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

	// MODE_WORLD_READABLE = 1, MODE_WORLD_WRITEABLE = 2 (both `static final int`, folded to literals
	// by javac/d8, so jadx emits `openFileOutput("f", 1)` and the identifier NEVER appears). The old
	// identifier-only `MODE_WORLD_READABLE` arm was dead code. The literal arms match the mode arg of
	// openFileOutput / getSharedPreferences / getDir — mode 1 (READABLE), 3 (READABLE|WRITABLE). The
	// setReadable(true,false) / chmod 644 arms stay (non-folded). Package-private for testing.
	static final Pattern WORLD_READABLE = Pattern.compile(
			"openFileOutput\\s*\\([^,]*,\\s*(?:1|3)\\b|getSharedPreferences\\s*\\([^,]*,\\s*(?:1|3)\\b|getDir\\s*\\([^,]*,\\s*(?:1|3)\\b|"
					+ "MODE_WORLD_READABLE|setReadable\\s*\\(\\s*true\\s*,\\s*false|chmod\\s+644|chmod\\s+664");
	// MODE_WORLD_WRITEABLE = 2; mode 2 (WRITABLE), 3 (READABLE|WRITABLE), 6 (WRITABLE|PRIVATE bit? —
	// actually MODE_WORLD_WRITEABLE|MODE_PRIVATE=2|0=2; the |3| case is shared with READABLE above).
	static final Pattern WORLD_WRITABLE = Pattern.compile(
			"openFileOutput\\s*\\([^,]*,\\s*(?:2|3)\\b|getSharedPreferences\\s*\\([^,]*,\\s*(?:2|3)\\b|getDir\\s*\\([^,]*,\\s*(?:2|3)\\b|"
					+ "MODE_WORLD_WRITEABLE|setWritable\\s*\\(\\s*true\\s*,\\s*false|chmod\\s+666|chmod\\s+646");
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

	/**
	 * Overly-broad FileProvider path declarations in a {@code res/xml/file_paths.xml} resource.
	 * {@code <root-path path=""/>} exposes the entire filesystem root; {@code <external-path ... path="/"/>}
	 * or {@code path=""} exposes all of external storage; {@code grant-all-permissions} in the provider
	 * tag widens every granted URI. Combined with {@code FLAG_GRANT_READ_URI_PERMISSION} any holder of the
	 * content URI reads/arbitrarily many files (CWE-22 / CWE-732, MASVS MSTG-STORAGE-10). The old
	 * {@code file_provider_misconfig} rule only flagged FileProvider *usage* in code with an info
	 * "verify path config" note — it never read the path XML, so a real root-path exposure passed silently.
	 * Package-private for testing.
	 */
	static final Pattern BROAD_FILE_PATH = Pattern.compile(
			"<root-path\\b|"
					+ "<external-path\\b[^>]*\\bpath\\s*=\\s*\"(?:/|\"|\\s*\")|"
					+ "<external-cache-path\\b[^>]*\\bpath\\s*=\\s*\"(?:/|\"|\\s*\")|"
					+ "<external-files-path\\b[^>]*\\bpath\\s*=\\s*\"(?:/|\"|\\s*\")|"
					+ "<files-path\\b[^>]*\\bpath\\s*=\\s*\"(?:/|\"|\\s*\")|"
					+ "<cache-path\\b[^>]*\\bpath\\s*=\\s*\"(?:/|\"|\\s*\")|"
					+ "grant-all-permissions");
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

		// Resource scan: a FileProvider path XML declaring a root/external-root path exposes the whole
		// filesystem (CWE-22/CWE-732) — the code-level file_provider_misconfig/info rule can't see this;
		// the path config lives in res/xml/file_paths.xml, decoded as an XML resource. ONE per resource.
		if (findings.size() < limit) {
			TreeSet<String> reportedResources = new TreeSet<>();
			for (ResourceFile res : decompiler.getResources()) {
				if (findings.size() >= limit) {
					break;
				}
				ResourceType type = res.getType();
				if (type != ResourceType.XML) {
					continue;
				}
				String name = res.getOriginalName();
				// FileProvider path configs live in res/xml/*paths*.xml; also scan any XML mentioning a
				// path element to catch renamed configs. Dedup by resource name.
				if (reportedResources.contains(name)) {
					continue;
				}
				String text;
				try {
					var container = res.loadContent();
					if (container == null) {
						continue;
					}
					var codeInfo = container.getText();
					if (codeInfo == null) {
						continue;
					}
					text = codeInfo.toString();
				} catch (Exception e) {
					continue;
				}
				if (!BROAD_FILE_PATH.matcher(text).find()) {
					continue;
				}
				reportedResources.add(name);
				findings.add(finding("file_provider_misconfig", "high", name, 0,
						"FileProvider path XML declares an overly-broad path (root-path / external-path "
								+ "with path=\"/\" or \"\") or grant-all-permissions — combined with "
								+ "FLAG_GRANT_READ_URI_PERMISSION any URI holder reads the entire filesystem "
								+ "root or external storage (CWE-22/CWE-732); scope paths to a specific subdir"));
				highSeverityCount++;
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
