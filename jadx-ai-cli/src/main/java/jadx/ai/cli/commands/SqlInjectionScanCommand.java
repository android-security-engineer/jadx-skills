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
 * Scans decompiled code for SQL injection in local SQLite access — MASVS MSTG-CODE, a sink class no
 * other scanner here covers ({@link StorageScanCommand} flags an <em>unencrypted</em> database, not
 * an <em>injectable</em> one). Native: reads jadx's parsed model, no external tool.
 *
 * <p>The vulnerability is a query whose SQL text is assembled by string concatenation with
 * untrusted input instead of using {@code ?} placeholders + {@code selectionArgs}. jadx reconstructs
 * the original {@code "..." + x + "..."} concatenation (or the {@code StringBuilder} the compiler
 * lowered it to) onto the call line, so the detection is: a SQLite query/exec sink whose argument
 * on that line contains string concatenation (a {@code "} adjacent to a {@code +}).
 *
 * <p>To keep the signal high, scanning is scoped to classes that actually touch SQLite (the same
 * "only flag in relevant classes" tactic {@link CryptoScanCommand} uses for insecure-RNG). Sinks:
 * <ul>
 *   <li>{@code rawQuery(...)} / {@code rawQueryWithFactory(...)} with concatenation — high</li>
 *   <li>{@code execSQL(...)} / {@code execPerConnectionSQL(...)} with concatenation — high</li>
 *   <li>{@code compileStatement(...)} with concatenation — high</li>
 *   <li>{@code db.query(...)} / {@code queryWithFactory(...)} where the selection is concatenated — medium</li>
 *   <li>{@code db.delete(table, whereClause, ...)} / {@code db.update(table, values, whereClause, ...)}
 *       where the whereClause (or table) is concatenated — high; the whereClause sink is a classic
 *       CWE-89 carrier on Android and was previously uncovered</li>
 *   <li>{@code db.insert(table, ...)} where the table name is concatenated — medium</li>
 *   <li>a bare SQL-keyword string literal ({@code SELECT/INSERT/UPDATE/DELETE/WHERE ...}) assembled
 *       by concatenation, even when the sink is on another line — medium</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * truncated}}.
 */
@Command(name = "sql-injection-scan",
		description = "Scan SQLite code for SQL injection (rawQuery/execSQL/query/compileStatement built via string concatenation)")
public class SqlInjectionScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** A class that touches SQLite at all — scope the scan here to avoid false positives. */
	private static final Pattern SQLITE_MARKER = Pattern.compile(
			"SQLiteDatabase|SQLiteOpenHelper|rawQuery|execSQL|getReadableDatabase|getWritableDatabase|compileStatement|android\\.database\\.sqlite");

	/** Two string fragments joined by {@code +} — the concatenation that makes a query injectable. */
	private static final Pattern CONCAT = Pattern.compile("\"\\s*\\+|\\+\\s*\"");

	/**
	 * A query argument built dynamically on the same line as a SQL sink, but NOT via {@code +} —
	 * {@code String.format}, {@code StringBuilder.append}, {@code .concat}, or {@code MessageFormat}.
	 * Same injection class as {@code +} concatenation, but {@code CONCAT} does not match it, so the line
	 * hit {@code if (!concat) continue;} and the finding was dropped entirely (e.g.
	 * {@code db.rawQuery(String.format("SELECT ... WHERE name='%s'", name), null)}). Matched only inside
	 * a SQL-sink argument (up to the next {@code ;}) so a {@code String.format} used elsewhere on the
	 * line is not a false positive.
	 */
	static final Pattern SQL_DYNAMIC_ARG = Pattern.compile(
			"(?:rawQuery(?:WithFactory)?\\s*\\(|execSQL\\s*\\(|execPerConnectionSQL\\s*\\(|compileStatement\\s*\\(|\\.query(?:WithFactory)?\\s*\\(|\\.delete\\s*\\(|\\.update\\s*\\(|\\.insert(?:OrThrow)?\\s*\\(|\\.replace\\s*\\()[^;]*?"
					+ "(?:String\\.format|MessageFormat|new\\s+StringBuilder)"
					+ "|(?:rawQuery(?:WithFactory)?\\s*\\(|execSQL\\s*\\(|execPerConnectionSQL\\s*\\(|compileStatement\\s*\\(|\\.query(?:WithFactory)?\\s*\\(|\\.delete\\s*\\(|\\.update\\s*\\(|\\.insert(?:OrThrow)?\\s*\\(|\\.replace\\s*\\()[^;]*?"
					+ "\\.(?:concat|append)\\s*\\(");

	private static final Pattern RAW_QUERY = Pattern.compile("rawQuery(WithFactory)?\\s*\\(");
	private static final Pattern EXEC_SQL = Pattern.compile("execSQL\\s*\\(|execPerConnectionSQL\\s*\\(");
	private static final Pattern COMPILE_STMT = Pattern.compile("compileStatement\\s*\\(");
	private static final Pattern DB_QUERY = Pattern.compile("\\.query(WithFactory)?\\s*\\(");
	/** {@code delete}/{@code update} — the whereClause (2nd/3rd arg) is a classic SQL-injection carrier. Package-private for testing. */
	static final Pattern DB_DELETE_OR_UPDATE = Pattern.compile("\\.delete\\s*\\(|\\.update\\s*\\(");
	/** {@code insert} — the table name (1st arg) is rarely concatenated; medium when it is. Package-private for testing. */
	static final Pattern DB_INSERT = Pattern.compile("\\.insert\\s*\\(|\\.insertOrThrow\\s*\\(|\\.replace\\s*\\(");
	private static final Pattern SQL_KEYWORD_LITERAL = Pattern.compile(
			"(?i)\"[^\"]*\\b(select |insert into|update |delete from|drop table|drop |where | from )[^\"]*\"");

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
			if (code == null || code.isEmpty() || !SQLITE_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;
				boolean concat = isSqlConcatenation(line);
				if (!concat) {
					continue; // injection requires concatenation; a parameterized/static query is safe
				}

				Map<String, Object> f = null;
				if (RAW_QUERY.matcher(line).find()) {
					f = finding(fullName, ln, "sql_injection", "high",
							"rawQuery built with string concatenation — use ? placeholders + selectionArgs");
				} else if (EXEC_SQL.matcher(line).find()) {
					f = finding(fullName, ln, "sql_injection", "high",
							"execSQL built with string concatenation — use bound parameters");
				} else if (COMPILE_STMT.matcher(line).find()) {
					f = finding(fullName, ln, "sql_injection", "high",
							"compileStatement SQL built with string concatenation — bind values instead");
				} else if (DB_QUERY.matcher(line).find()) {
					f = finding(fullName, ln, "sql_injection", "medium",
							"SQLiteDatabase.query selection/args built with concatenation — pass a parameterized selection");
				} else if (DB_DELETE_OR_UPDATE.matcher(line).find()) {
					f = finding(fullName, ln, "sql_injection", "high",
							"SQLiteDatabase.delete/update whereClause (or table) built with concatenation — use ? placeholders + whereArgs; the whereClause is a classic SQL-injection carrier");
				} else if (DB_INSERT.matcher(line).find()) {
					f = finding(fullName, ln, "sql_injection", "medium",
							"SQLiteDatabase.insert/replace table name built with concatenation — verify the table name is never attacker-controlled");
				} else if (SQL_KEYWORD_LITERAL.matcher(line).find()) {
					f = finding(fullName, ln, "sql_string_concat", "medium",
							"SQL statement string assembled via concatenation — verify it never reaches a query sink with untrusted input");
				}

				if (f != null) {
					if ("high".equals(f.get("severity"))) {
						highSeverityCount++;
					}
					findings.add(f);
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	/**
	 * True if the line builds a SQL argument dynamically — either literal-variable {@code +}
	 * concatenation, or a {@code String.format}/{@code StringBuilder.append}/{@code .concat}/
	 * {@code MessageFormat} form feeding a SQL sink. Package-private so a test can assert both forms
	 * fire and a parameterized query does not.
	 */
	static boolean isSqlConcatenation(String line) {
		if (line == null) {
			return false;
		}
		return CONCAT.matcher(line).find() || SQL_DYNAMIC_ARG.matcher(line).find();
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
		return "sql-injection-scan";
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
