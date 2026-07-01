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
 * Scans {@code ContentProvider} implementations for injection / traversal — MASVS MSTG-PLATFORM-2.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>A {@code ContentProvider} is a <em>remotely-reachable attack surface</em>: any app (and, if
 * exported, any installed package) can hit its {@code content://} authority. So an SQL string built
 * from the incoming {@code Uri}/{@code selection}, or an {@code openFile} that maps a URI segment to
 * a {@code File} path, is not a local bug — it is an IPC-reachable SQLi / arbitrary-file-read. This
 * scanner is scoped to provider classes (it would be noise in ordinary DB code) and keys on
 * <em>URI-derived</em> untrusted input, which is what makes the finding provider-specific. Pairs
 * with {@code manifest-audit} (which flags the {@code android:exported}/permission gap statically)
 * and complements {@code sql-injection-scan} / {@code path-traversal-scan} (which are not
 * provider-aware).
 * <ul>
 *   <li><b>provider_sql_injection</b> (high) — {@code query/insert/update/delete/rawQuery/execSQL}
 *       or {@code SQLiteQueryBuilder.appendWhere/setTables} built by string-concatenation inside a
 *       provider — IPC-reachable SQL injection.</li>
 *   <li><b>provider_path_traversal</b> (high) — {@code openFile/openAssetFile} that derives a
 *       {@code File} from {@code uri.getPathSegments/getLastPathSegment/getPath} with no canonical
 *       guard — IPC-reachable arbitrary file read/write. The URI-source and the {@code new File}/
 *       {@code ParcelFileDescriptor.open} sink are matched at <em>class</em> scope, because a real
 *       openFile pulls the path segment on one line and builds the File on another; a same-line AND
 *       would silently drop the finding on the common form.</li>
 *   <li><b>provider_world_grant</b> (medium) — {@code grantUriPermission} /
 *       {@code FLAG_GRANT_*_URI_PERMISSION} / {@code setGrantUriPermissions} widening access.</li>
 *   <li><b>provider_uri_trusted</b> (info) — reads {@code uri.getLastPathSegment}/etc. into a query;
 *       a hotspot to review even when concatenation isn't obvious on one line.</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * providerClasses, truncated}}.
 */
@Command(name = "exported-provider-scan",
		description = "Scan ContentProvider implementations for IPC-reachable SQLi (concat into query/appendWhere) and openFile path traversal (URI segment → File). Provider-scoped; pairs with manifest-audit (exported flags)")
public class ExportedProviderScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Class-level gate: only ContentProvider implementations. */
	private static final Pattern PROVIDER_MARKER = Pattern.compile(
			"extends\\s+ContentProvider|ContentProvider|SQLiteQueryBuilder|"
					+ "public\\s+Cursor\\s+query\\s*\\(\\s*Uri|openFile\\s*\\(\\s*Uri|getType\\s*\\(\\s*Uri");

	// String concatenation on a line: a quote adjacent to a + (or + adjacent to a quote).
	private static final Pattern CONCAT = Pattern.compile("\"\\s*\\+|\\+\\s*\"");

	/**
	 * A provider SQL argument built dynamically on the same line as a SQL sink, but NOT via {@code +} —
	 * {@code String.format}, {@code StringBuilder.append}, {@code .concat}, or {@code MessageFormat}.
	 * Same IPC-reachable injection class as {@code +} concatenation, but {@code CONCAT} does not match
	 * it, so the line fell through to {@code provider_uri_trusted/info} instead of
	 * {@code provider_sql_injection/high} (e.g. {@code db.rawQuery(String.format("...WHERE id=%s",
	 * uri.getLastPathSegment()), null)}). Matched only inside a SQL-sink argument (up to the next
	 * {@code ;}) so a {@code String.format} used elsewhere on the line is not a false positive.
	 * Package-private for testing.
	 */
	static final Pattern PROVIDER_SQL_DYNAMIC_ARG = Pattern.compile(
			"(?:appendWhere\\s*\\(|setTables\\s*\\(|compileStatement\\s*\\(|"
					+ "\\.rawQuery\\s*\\(|\\.execSQL\\s*\\(|\\.query\\s*\\(|\\.insert\\s*\\(|\\.update\\s*\\(|\\.delete\\s*\\()[^;]*?"
					+ "(?:String\\.format|MessageFormat|new\\s+StringBuilder)"
					+ "|(?:appendWhere\\s*\\(|setTables\\s*\\(|compileStatement\\s*\\(|"
					+ "\\.rawQuery\\s*\\(|\\.execSQL\\s*\\(|\\.query\\s*\\(|\\.insert\\s*\\(|\\.update\\s*\\(|\\.delete\\s*\\()[^;]*?"
					+ "\\.(?:concat|append)\\s*\\(");

	private static final Pattern SQL_SINK = Pattern.compile(
			"\\.rawQuery\\s*\\(|\\.execSQL\\s*\\(|\\.query\\s*\\(|appendWhere\\s*\\(|setTables\\s*\\(|"
					+ "\\.insert\\s*\\(|\\.update\\s*\\(|\\.delete\\s*\\(|compileStatement\\s*\\(");
	/** File-construction / open sinks inside an openFile implementation. Package-private for testing. */
	static final Pattern FILE_SINK = Pattern.compile(
			"new\\s+File\\s*\\(|ParcelFileDescriptor\\.open|openFileHelper\\s*\\(");
	private static final Pattern OPENFILE_CTX = Pattern.compile("openFile\\s*\\(|openAssetFile\\s*\\(");
	/**
	 * Untrusted URI-derived path input. Matched at <em>class</em> scope for path-traversal (a real
	 * openFile reads the path segment on one line and builds the File on another). Package-private for
	 * testing.
	 */
	static final Pattern URI_SOURCE = Pattern.compile(
			"uri\\.getPathSegments|getLastPathSegment|uri\\.getPath|getPathSegments\\s*\\(|"
					+ "uri\\.getQueryParameter|ContentUris\\.parseId");
	/** A canonical-path / normalize / prefix-bound guard that suppresses path traversal. Package-private for testing. */
	static final Pattern CANONICAL_GUARD = Pattern.compile(
			"getCanonicalPath|getCanonicalFile|toRealPath|normalize\\s*\\(|\\.startsWith\\s*\\(");
	private static final Pattern GRANT = Pattern.compile(
			"grantUriPermission\\s*\\(|FLAG_GRANT_(READ|WRITE)_URI_PERMISSION|setGrantUriPermissions");

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
		int providerClasses = 0;

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
			providerClasses++;

			// A canonical/normalize/startsWith guard anywhere in the class suppresses the
			// path-traversal class (the class is validating its file paths).
			boolean classGuardsPath = CANONICAL_GUARD.matcher(code).find();
			boolean classHasOpenFile = OPENFILE_CTX.matcher(code).find();
			// URI_SOURCE is matched at CLASS scope: a real openFile reads the path segment on one line
			// and builds the File on another, so a same-line FILE_SINK ∧ URI_SOURCE AND would miss the
			// common form. The FILE_SINK line stays the per-line anchor for lineNumber.
			boolean classHasUriSource = URI_SOURCE.matcher(code).find();

			String[] lines = code.split("\n", -1);
			boolean reportedPathTraversal = false;
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;

				// Dynamic argument construction: either + concatenation (CONCAT) or a
				// String.format/StringBuilder/.concat form feeding a SQL sink (PROVIDER_SQL_DYNAMIC_ARG).
				// Both are the same IPC-reachable injection class; the dynamic-arg form was previously
				// missed because CONCAT does not match String.format.
				boolean concat = CONCAT.matcher(line).find() || PROVIDER_SQL_DYNAMIC_ARG.matcher(line).find();

				if (SQL_SINK.matcher(line).find() && concat) {
					findings.add(finding(fullName, ln, "provider_sql_injection", "high",
							"SQL built by string-concatenation inside a ContentProvider — IPC-reachable SQL injection (any app can hit this content:// authority). Use parameterized selectionArgs / SQLiteQueryBuilder with bound args"));
					highSeverityCount++;
					continue;
				}
				if (!reportedPathTraversal
						&& providerPathTraversalSignal(classHasOpenFile, classHasUriSource, classGuardsPath, line)) {
					findings.add(finding(fullName, ln, "provider_path_traversal", "high",
							"openFile/openAssetFile maps a URI segment to a File with no canonical-path guard — IPC-reachable arbitrary file read/write via ../ in the content:// path. Canonicalise and confine to an allowed root"));
					highSeverityCount++;
					reportedPathTraversal = true;
					continue;
				}
				if (GRANT.matcher(line).find()) {
					findings.add(finding(fullName, ln, "provider_world_grant", "medium",
							"grantUriPermission / FLAG_GRANT_*_URI_PERMISSION widens provider access — verify the grant is scoped to a specific URI and recipient, not blanket"));
					continue;
				}
				if (URI_SOURCE.matcher(line).find()) {
					findings.add(finding(fullName, ln, "provider_uri_trusted", "info",
							"Reads an untrusted URI segment (getLastPathSegment / getPathSegments / parseId) — review how it flows into the query/file path"));
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("providerClasses", providerClasses);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	/**
	 * True if {@code line} is the anchor for a provider path-traversal finding. The class-level facts
	 * (openFile present, URI-derived input present somewhere in the class, no canonical guard) are
	 * passed in; this method only checks the per-line File sink that gives the finding its lineNumber.
	 *
	 * <p>Package-private so a test can assert the cross-line fix: a class whose URI_SOURCE and FILE_SINK
	 * are on different lines now fires (when guarded it does not).
	 */
	static boolean providerPathTraversalSignal(boolean classHasOpenFile, boolean classHasUriSource,
			boolean classGuardsPath, String line) {
		return classHasOpenFile && classHasUriSource && !classGuardsPath
				&& line != null && FILE_SINK.matcher(line).find();
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
		return "exported-provider-scan";
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
