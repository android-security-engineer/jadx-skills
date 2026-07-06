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
 * Scans decompiled code for path-traversal and Zip Slip sinks — MASVS MSTG-CODE / MSTG-PLATFORM.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Two distinct bug classes share the same root cause (a file path built from attacker-controlled
 * data and used without canonicalising/validating it against a base directory):
 * <ul>
 *   <li><b>Zip Slip</b> — when a class unpacks an archive ({@code ZipInputStream}/{@code ZipEntry}/
 *       {@code ZipFile}, using {@code entry.getName()}) and writes entries to a {@code File} path
 *       <em>without</em> a canonical-path guard, a crafted entry name like {@code ../../x} escapes
 *       the extraction directory. High.</li>
 *   <li><b>Untrusted path</b> — a file sink ({@code new File}, {@code FileInputStream/OutputStream},
 *       {@code RandomAccessFile}, {@code openFileOutput}) on a line that also reads an untrusted
 *       source ({@code getStringExtra}, {@code getQueryParameter}, {@code Uri.parse}, ...) with no
 *       canonical check. High.</li>
 *   <li>A literal {@code ../} path segment in code — low (smell / possible traversal payload).</li>
 * </ul>
 *
 * <p>Per-class suppression: a {@code getCanonicalPath()}/{@code getCanonicalFile()} (or a
 * {@code startsWith} prefix check) anywhere in the class is treated as a validation guard and drops
 * the high-severity zip/untrusted findings to avoid false positives on code that does validate.
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * zipSlipCount, truncated}}.
 */
@Command(name = "path-traversal-scan",
		description = "Scan code for path traversal & Zip Slip (untrusted file paths, archive entry extraction without canonicalisation)")
public class PathTraversalScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Class must touch the filesystem at all to be worth scanning. */
	private static final Pattern FILE_MARKER = Pattern.compile(
			"new\\s+File\\s*\\(|FileInputStream|FileOutputStream|RandomAccessFile|openFileOutput\\s*\\(|FileReader|FileWriter|ZipEntry|ZipInputStream|ZipFile");

	/** Archive-extraction context (Zip Slip only applies here). */
	private static final Pattern ZIP_MARKER = Pattern.compile(
			"ZipInputStream|ZipEntry|ZipFile|getNextEntry\\s*\\(|java\\.util\\.zip|TarArchiveInputStream|ArchiveEntry");

	private static final Pattern ENTRY_NAME = Pattern.compile("\\.getName\\s*\\(");

	/** A canonicalisation / prefix guard anywhere in the class suppresses the high findings. */
	static final Pattern CANONICAL_GUARD = Pattern.compile(
			"getCanonicalPath\\s*\\(|getCanonicalFile\\s*\\(|toRealPath\\s*\\(|normalize\\s*\\(\\s*\\)|\\.startsWith\\s*\\(");

	/** File-system sinks that consume a path/name. */
	private static final Pattern FILE_SINK = Pattern.compile(
			"new\\s+File\\s*\\(|new\\s+FileInputStream\\s*\\(|new\\s+FileOutputStream\\s*\\(|new\\s+RandomAccessFile\\s*\\(|openFileOutput\\s*\\(|new\\s+FileReader\\s*\\(|new\\s+FileWriter\\s*\\(");

	/** Attacker-controllable sources of a path/name — matched at CLASS scope for path_traversal: a real
	 * handler reads the untrusted input (getStringExtra/getQueryParameter/Uri.parse/...) on one line
	 * and opens the File on another, so a same-line sink∧source AND would miss the common form.
	 * Package-private so a test can assert the cross-line fix. */
	static final Pattern UNTRUSTED = Pattern.compile(
			"getStringExtra\\s*\\(|getQueryParameter\\s*\\(|getParameter\\s*\\(|getIntent\\s*\\(\\s*\\)|getData\\s*\\(\\s*\\)|getExtras\\s*\\(|getHeader\\s*\\(|Uri\\.parse\\s*\\(|getLastPathSegment\\s*\\(|getPath\\s*\\(\\s*\\)|getInputStream\\s*\\(");

	/**
	 * True iff the line is a file sink and the class takes an attacker-controlled path with no
	 * canonical guard — the cross-line path_traversal signal. Package-private for testing.
	 */
	static boolean untrustedPathSignal(boolean classHasUntrusted, boolean classGuardsPath, String line) {
		return classHasUntrusted && !classGuardsPath && line != null && FILE_SINK.matcher(line).find();
	}

	private static final Pattern TRAVERSAL_LITERAL = Pattern.compile("\"[^\"]*\\.\\./[^\"]*\"|\"\\.\\.\"");

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
		int zipSlipCount = 0;

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

			boolean isZipCtx = ZIP_MARKER.matcher(code).find() && ENTRY_NAME.matcher(code).find();
			boolean hasGuard = CANONICAL_GUARD.matcher(code).find();
			// UNTRUSTED source is matched at CLASS scope: a real handler reads the input on one line and
			// opens the File on another, so a same-line sink∧source AND would miss the common form.
			boolean classHasUntrusted = UNTRUSTED.matcher(code).find();
			boolean reportedPathTraversal = false;

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;
				boolean sink = FILE_SINK.matcher(line).find();

				// Zip Slip: a file sink inside an archive-extraction class with no canonical guard.
				if (sink && isZipCtx && !hasGuard) {
					findings.add(finding(fullName, ln, "zip_slip", "high",
							"Archive entry written to a File path without canonical-path validation (Zip Slip) — a crafted entry name like ../../x escapes the extraction directory"));
					highSeverityCount++;
					zipSlipCount++;
					continue;
				}

				// Untrusted path: a file sink in a class that takes attacker-controlled input, with no
				// canonical guard. Class-scoped source covers both the same-line and the cross-line
				// (String p = intent.getStringExtra(...); new File(p)) forms.
				if (!reportedPathTraversal && untrustedPathSignal(classHasUntrusted, hasGuard, line)) {
					findings.add(finding(fullName, ln, "path_traversal", "high",
							"File path derived from untrusted input (intent extra / query param / Uri) without canonicalisation — attacker can traverse with ../"));
					highSeverityCount++;
					reportedPathTraversal = true;
					continue;
				}

				// Literal ../ segment — weak smell, reported low.
				if (TRAVERSAL_LITERAL.matcher(line).find()) {
					findings.add(finding(fullName, ln, "traversal_literal", "low",
							"Literal ../ path segment in code — possible hand-rolled traversal or a payload constant"));
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("zipSlipCount", zipSlipCount);
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
		return "path-traversal-scan";
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
