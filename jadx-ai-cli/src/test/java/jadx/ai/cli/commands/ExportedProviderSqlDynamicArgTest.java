package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code provider_sql_injection} dynamic-arg form in
 * {@link ExportedProviderScanCommand#PROVIDER_SQL_DYNAMIC_ARG}.
 *
 * <p>Before this, {@code provider_sql_injection} required a {@code +}-concatenation (CONCAT) on the
 * same line as a SQL sink. A provider that built its query with {@code String.format}/
 * {@code StringBuilder.append}/{@code .concat} — the same IPC-reachable injection class — fell
 * through to {@code provider_uri_trusted/info}, silently dropping the high finding. This mirrors the
 * {@code SqlInjectionScanCommand#SQL_DYNAMIC_ARG} fix, scoped to the provider SQL-sink set (which
 * also includes {@code appendWhere}/{@code setTables}).
 */
class ExportedProviderSqlDynamicArgTest {

	private static final Pattern DYN = Pattern.compile(ExportedProviderScanCommand.PROVIDER_SQL_DYNAMIC_ARG.pattern());

	private static boolean fires(String line) {
		return DYN.matcher(line).find();
	}

	@Test
	void rawQueryStringFormatFires() {
		assertTrue(fires("Cursor c = db.rawQuery(String.format(\"SELECT * FROM t WHERE id=%s\", uri.getLastPathSegment()), null);"),
				"a String.format query in a ContentProvider is IPC-reachable SQLi — must fire");
	}

	@Test
	void appendWhereStringBuilderFires() {
		assertTrue(fires("qb.appendWhere(new StringBuilder(\"id=\").append(uri.getLastPathSegment()).toString());"),
				"appendWhere built with StringBuilder.append is provider SQLi — must fire");
	}

	@Test
	void setTablesConcatMethodFires() {
		assertTrue(fires("qb.setTables(\"t_\".concat(uri.getQueryParameter(\"name\")));"),
				"setTables built with .concat is provider SQLi — must fire (dynamic-arg .concat arm)");
	}

	@Test
	void execSqlStringFormatFires() {
		assertTrue(fires("db.execSQL(String.format(\"DELETE FROM t WHERE id=%s\", id));"),
				"execSQL with String.format in a provider must fire");
	}

	@Test
	void staticRawQueryDoesNotFire() {
		assertFalse(fires("Cursor c = db.rawQuery(\"SELECT * FROM t WHERE id=?\", args);"),
				"a parameterized rawQuery (no dynamic construction) is safe — must not fire");
	}

	@Test
	void stringFormatOutsideSqlSinkDoesNotFire() {
		assertFalse(fires("Log.i(TAG, String.format(\"rows=%d\", n));"),
				"String.format not feeding a provider SQL sink is not injection");
	}

	@Test
	void staticQueryWithUnrelatedStringFormatAfterSemicolonDoesNotFire() {
		// The [^;]*? boundary blocks cross-statement FP: a parameterized query followed by an
		// unrelated String.format after the ';' must NOT fire.
		assertFalse(fires("db.rawQuery(\"SELECT * FROM t WHERE id=?\", args); Log.i(TAG, String.format(\"n=%d\", n));"),
				"a parameterized query must not fire just because an unrelated String.format sits after the ; on the same line");
	}
}
