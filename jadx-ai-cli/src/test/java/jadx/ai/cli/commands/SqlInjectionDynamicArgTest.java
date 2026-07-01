package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the dynamic-arg-form fix in {@link SqlInjectionScanCommand}.
 *
 * <p>Before the fix, only {@code " +} / {@code + "} concatenation set {@code concat=true}, and a line
 * with no such concatenation hit {@code if (!concat) continue;} — so a query built with
 * {@code String.format} / {@code StringBuilder.append} / {@code .concat} and fed into
 * {@code rawQuery/execSQL/compileStatement/query} was dropped entirely instead of flagged as injection.
 */
class SqlInjectionDynamicArgTest {

	private static boolean concat(String line) {
		return SqlInjectionScanCommand.isSqlConcatenation(line);
	}

	@Test
	void literalPlusConcatStillFires() {
		assertTrue(concat("db.rawQuery(\"SELECT * FROM t WHERE n=\" + name, null);"),
				"literal+variable concatenation must still fire");
	}

	@Test
	void stringFormatRawQueryFires() {
		assertTrue(concat("db.rawQuery(String.format(\"SELECT * FROM t WHERE n='%s'\", name), null);"),
				"String.format feeding rawQuery is dynamic concatenation — must fire, not be dropped");
	}

	@Test
	void stringBuilderAppendExecSqlFires() {
		assertTrue(concat("db.execSQL(new StringBuilder(\"UPDATE t SET v=\").append(v).toString());"),
				"StringBuilder.append feeding execSQL is dynamic concatenation — must fire");
	}

	@Test
	void concatMethodQueryFires() {
		assertTrue(concat("db.query(\"t\".concat(\" WHERE n=?\"), null, null, null, null);"),
				".concat feeding query is dynamic concatenation — must fire");
	}

	@Test
	void parameterizedQueryDoesNotFire() {
		assertFalse(concat("db.rawQuery(\"SELECT * FROM t WHERE n=?\", new String[]{name});"),
				"a parameterized query (no concatenation) is safe");
		assertFalse(concat("db.query(\"t\", null, \"n=?\", new String[]{name}, null, null, null);"),
				"a parameterized query is safe");
	}

	@Test
	void stringFormatOutsideSqlSinkDoesNotFire() {
		assertFalse(concat("Log.i(TAG, String.format(\"rows=%d\", n));"),
				"String.format not feeding a SQL sink is not SQL concatenation");
	}
}
