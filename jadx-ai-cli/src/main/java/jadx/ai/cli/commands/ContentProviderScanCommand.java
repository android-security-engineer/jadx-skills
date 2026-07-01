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
 *   <li>{@code sql_injection_provider} — string concatenation in {@code query()} where the
 *       selection/orderBy arguments are used directly in raw SQL</li>
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

	private static final Pattern QUERY_METHOD = Pattern.compile(
			"public\\s+Cursor\\s+query\\s*\\(");
	private static final Pattern INSERT_METHOD = Pattern.compile(
			"public\\s+Uri\\s+insert\\s*\\(");
	private static final Pattern UPDATE_METHOD = Pattern.compile(
			"public\\s+int\\s+update\\s*\\(");
	private static final Pattern DELETE_METHOD = Pattern.compile(
			"public\\s+int\\s+delete\\s*\\(");
	private static final Pattern OPEN_FILE_METHOD = Pattern.compile(
			"public\\s+ParcelFileDescriptor\\s+openFile\\s*\\(");

	/** Caller validation patterns. */
	private static final Pattern CALLER_CHECK = Pattern.compile(
			"getCallingPackage\\s*\\(|getCallingUid\\s*\\(|checkCallingPermission|enforceCallingPermission|"
					+ "checkPermission|enforcePermission|checkCallingOrSelfPermission");

	/** SQL concatenation in query(). */
	private static final Pattern SQL_CONCAT = Pattern.compile(
			"\\+\\s*selection|selection\\s*\\+|\\+\\s*sortOrder|sortOrder\\s*\\+|"
					+ "rawQuery\\s*\\(|execSQL\\s*\\(");

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

			// SQL injection in query()
			if (hasQuery && SQL_CONCAT.matcher(code).find()) {
				findings.add(finding("sql_injection_provider", "high", fullName, 0,
						"String concatenation / rawQuery in ContentProvider.query() — "
								+ "selection/sortOrder arguments may enable SQL injection; "
								+ "use parameterized queries"));
				highSeverityCount++;
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
