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
 * ContentProvider access-control scanner — MASVS MSTG-STORAGE-6.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code exported-provider-scan} (inventories exported ContentProviders from
 * the manifest) and {@code storage-scan} (insecure storage API usage — SharedPreferences,
 * cleartext files). This scanner focuses on <b>ContentProvider access-control defects</b>:
 * exported providers that do not verify the caller's identity or enforce path-permission
 * restrictions in their CRUD methods.
 *
 * <p>Categories:
 * <ul>
 *   <li>{@code unvalidated_query} — {@code query()} method in an exported ContentProvider
 *       that does not check {@code getCallingPackage()} or {@code getCallingUid()} — any app
 *       can read the data</li>
 *   <li>{@code unvalidated_insert} — {@code insert()} without caller validation</li>
 *   <li>{@code unvalidated_update} — {@code update()} without caller validation</li>
 *   <li>{@code unvalidated_delete} — {@code delete()} without caller validation</li>
 *   <li>{@code sql_injection_provider} — a SQL sink (rawQuery/execSQL/query/appendWhere/setTables)
 *       on a line that builds its argument dynamically (+ concat, String.format, StringBuilder,
 *       or .concat) inside {@code query()} — selection/sortOrder arguments enable SQL injection;
 *       parameterized queries do not fire</li>
 *   <li>{@code path_traversal_provider} — {@code openFile()} that uses the URI path segment
 *       directly in a File constructor without validation</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, unvalidatedProviders, truncated}}.
 */
@Command(name = "content-provider-scan",
		description = "Detect ContentProvider access-control defects (MASVS MSTG-STORAGE-6): unvalidated query/insert/update/delete in exported providers, SQL injection in query(), path traversal in openFile(). Distinct from exported-provider-scan (manifest inventory) and storage-scan (insecure storage APIs)")
public class ContentProviderScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan ContentProvider classes. */
	private static final Pattern PROVIDER_MARKER = Pattern.compile(
			"ContentProvider|extends\\s+ContentProvider");

	/**
	 * ContentProvider CRUD / openFile method-signature anchors. jadx echoes {@code final}/{@code
	 * synchronized}/{@code static} method modifiers (AccessInfo.makeString) between {@code public} and
	 * the return type — a {@code public final Uri insert(...)} or {@code public synchronized Cursor
	 * query(...)} override is common for providers that lock or seal their CRUD methods — so the bare
	 * {@code public\s+ReturnType} form missed them and the method went unrecognised (losing
	 * unvalidated_insert / sql_injection_provider / etc.). The {@code (?:final|synchronized|static)\s+*}
	 * gap tolerates every modifier combo. Package-private for testing.
	 */
	static final Pattern QUERY_METHOD = Pattern.compile(
			"public\\s+(?:(?:final|synchronized|static)\\s+)*Cursor\\s+query\\s*\\(");
	static final Pattern INSERT_METHOD = Pattern.compile(
			"public\\s+(?:(?:final|synchronized|static)\\s+)*Uri\\s+insert\\s*\\(");
	static final Pattern UPDATE_METHOD = Pattern.compile(
			"public\\s+(?:(?:final|synchronized|static)\\s+)*int\\s+update\\s*\\(");
	static final Pattern DELETE_METHOD = Pattern.compile(
			"public\\s+(?:(?:final|synchronized|static)\\s+)*int\\s+delete\\s*\\(");
	static final Pattern OPEN_FILE_METHOD = Pattern.compile(
			"public\\s+(?:(?:final|synchronized|static)\\s+)*ParcelFileDescriptor\\s+openFile\\s*\\(");

	/** Caller validation patterns. */
	private static final Pattern CALLER_CHECK = Pattern.compile(
			"getCallingPackage\\s*\\(|getCallingUid\\s*\\(|checkCallingPermission|enforceCallingPermission|"
					+ "checkPermission|enforcePermission|checkCallingOrSelfPermission");

	/**
	 * String concatenation on a line: a quote adjacent to a {@code +} (or {@code +} adjacent to a quote).
	 * Any operand {@code +} form, not just the {@code selection}/{@code sortOrder} named ones the old
	 * {@code SQL_CONCAT} matched. Package-private for testing.
	 */
	static final Pattern CONCAT = Pattern.compile("\"\\s*\\+|\\+\\s*\"");

	/** A SQL sink reachable inside a provider's CRUD method. Package-private for testing. */
	static final Pattern SQL_SINK = Pattern.compile(
			"\\.rawQuery\\s*\\(|\\.execSQL\\s*\\(|\\.query\\s*\\(|appendWhere\\s*\\(|setTables\\s*\\(|"
					+ "\\.insert\\s*\\(|\\.update\\s*\\(|\\.delete\\s*\\(|compileStatement\\s*\\(");

	/**
	 * A provider SQL argument built dynamically on the same line as a SQL sink, but NOT via {@code +} —
	 * {@code String.format}, {@code StringBuilder.append}, {@code .concat}, or {@code MessageFormat}.
	 * Same IPC-reachable CWE-89 class as {@code +} concatenation, but {@link #CONCAT} does not match it,
	 * so the line fell through (e.g. {@code db.rawQuery(String.format("...WHERE id=%s", id), null)}).
	 * Matched only inside a SQL-sink argument (up to the next {@code ;}) so a {@code String.format} used
	 * elsewhere on the line is not a false positive. This mirrors {@code ExportedProviderScanCommand}'s
	 * {@code PROVIDER_SQL_DYNAMIC_ARG} (kept independent so each scanner stays self-contained) — the two
	 * were asymmetric: this command's old {@code SQL_CONCAT} only matched {@code +} of operands literally
	 * named {@code selection}/{@code sortOrder}, missing {@code String.format}/{@code StringBuilder}/
	 * {@code .concat} AND {@code +} of any other operand name. Package-private for testing.
	 */
	static final Pattern PROVIDER_SQL_DYNAMIC_ARG = Pattern.compile(
			"(?:appendWhere\\s*\\(|setTables\\s*\\(|compileStatement\\s*\\(|"
					+ "\\.rawQuery\\s*\\(|\\.execSQL\\s*\\(|\\.query\\s*\\(|\\.insert\\s*\\(|\\.update\\s*\\(|\\.delete\\s*\\()[^;]*?"
					+ "(?:String\\.format|MessageFormat|new\\s+StringBuilder)"
					+ "|(?:appendWhere\\s*\\(|setTables\\s*\\(|compileStatement\\s*\\(|"
					+ "\\.rawQuery\\s*\\(|\\.execSQL\\s*\\(|\\.query\\s*\\(|\\.insert\\s*\\(|\\.update\\s*\\(|\\.delete\\s*\\()[^;]*?"
					+ "\\.(?:concat|append)\\s*\\(");

	/** Path traversal in openFile(). */
	private static final Pattern FILE_FROM_URI = Pattern.compile(
			"new\\s+File\\s*\\(|FileInputStream\\s*\\(|FileOutputStream\\s*\\(");
	private static final Pattern URI_PATH_SEGMENT = Pattern.compile(
			"getPathSegments|getLastPathSegment|getPath\\s*\\(");

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
		TreeSet<String> unvalidatedProviders = new TreeSet<>();

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
			if (code == null || code.isEmpty() || !PROVIDER_MARKER.matcher(code).find()) {
				continue;
			}

			boolean classHasCallerCheck = CALLER_CHECK.matcher(code).find();
			boolean hasQuery = QUERY_METHOD.matcher(code).find();
			boolean hasInsert = INSERT_METHOD.matcher(code).find();
			boolean hasUpdate = UPDATE_METHOD.matcher(code).find();
			boolean hasDelete = DELETE_METHOD.matcher(code).find();
			boolean hasOpenFile = OPEN_FILE_METHOD.matcher(code).find();

			// Unvalidated CRUD methods
			if (!classHasCallerCheck) {
				if (hasQuery) {
					unvalidatedProviders.add(fullName);
					findings.add(finding("unvalidated_query", "high", fullName, 0,
							"ContentProvider.query() without caller validation (getCallingPackage/getCallingUid) — "
									+ "any app can read the provider's data"));
					highSeverityCount++;
				}
				if (hasInsert) {
					unvalidatedProviders.add(fullName);
					findings.add(finding("unvalidated_insert", "high", fullName, 0,
							"ContentProvider.insert() without caller validation — "
									+ "any app can insert data into the provider"));
					highSeverityCount++;
				}
				if (hasUpdate) {
					unvalidatedProviders.add(fullName);
					findings.add(finding("unvalidated_update", "high", fullName, 0,
							"ContentProvider.update() without caller validation — "
									+ "any app can modify the provider's data"));
					highSeverityCount++;
				}
				if (hasDelete) {
					unvalidatedProviders.add(fullName);
					findings.add(finding("unvalidated_delete", "high", fullName, 0,
							"ContentProvider.delete() without caller validation — "
									+ "any app can delete the provider's data"));
					highSeverityCount++;
				}
			}

			// SQL injection in query(): a SQL sink on a line that also builds its argument dynamically
			// (+ concatenation of any operand, OR String.format/StringBuilder/.concat). The old class-scope
			// SQL_CONCAT matched ANY rawQuery/execSQL call — flagging parameterized queries as a false
			// positive — while missing String.format/StringBuilder/.concat forms; this line-scope
			// sink+dynamic-construction form is precise (parameterized rawQuery("...?", args) does NOT fire)
			// and covers every dynamic-construction variant. ONE/class.
			if (hasQuery && findings.size() < limit) {
				boolean reportedSqlInj = false;
				String[] lines = code.split("\n", -1);
				for (int i = 0; i < lines.length && !reportedSqlInj; i++) {
					String line = lines[i];
					if (SQL_SINK.matcher(line).find()
							&& (CONCAT.matcher(line).find() || PROVIDER_SQL_DYNAMIC_ARG.matcher(line).find())) {
						findings.add(finding("sql_injection_provider", "high", fullName, i + 1,
								"SQL built by string-concatenation / String.format in ContentProvider.query() — "
										+ "selection/sortOrder arguments may enable SQL injection; "
										+ "use parameterized queries (selectionArgs)"));
						highSeverityCount++;
						reportedSqlInj = true;
					}
				}
			}

			// Path traversal in openFile()
			if (hasOpenFile && FILE_FROM_URI.matcher(code).find() && URI_PATH_SEGMENT.matcher(code).find()) {
				findings.add(finding("path_traversal_provider", "high", fullName, 0,
						"ContentProvider.openFile() constructs a File from URI path segments — "
								+ "path traversal risk (../); validate and canonicalize the path before opening"));
				highSeverityCount++;
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("unvalidatedProviders", new ArrayList<>(unvalidatedProviders));
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
		return "content-provider-scan";
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
