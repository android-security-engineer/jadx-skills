package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code delete}/{@code update}/{@code insert} whereClause/table sinks added to
 * {@link SqlInjectionScanCommand}.
 *
 * <p>The detector previously covered only {@code rawQuery}/{@code execSQL}/{@code compileStatement}/
 * {@code query}. But {@code SQLiteDatabase.delete(table, whereClause, whereArgs)} and
 * {@code update(table, values, whereClause, whereArgs)} take a {@code whereClause} argument that,
 * when built by concatenation or {@code String.format}, is a classic CWE-89 carrier on Android —
 * exactly as injectable as a concatenated {@code rawQuery}. Both the {@code +} form and the
 * {@code String.format}/{@code StringBuilder} form were silently missed because neither
 * {@link SqlInjectionScanCommand#CONCAT} nor {@link SqlInjectionScanCommand#SQL_DYNAMIC_ARG} listed
 * delete/update/insert as sinks.
 */
class SqlInjectionDeleteUpdateInsertTest {

	/** Mirrors execute()'s per-line gating: only a SQL sink whose argument is built dynamically fires. */
	private static boolean fires(String line) {
		return SqlInjectionScanCommand.isSqlConcatenation(line)
				&& (SqlInjectionScanCommand.DB_DELETE_OR_UPDATE.matcher(line).find()
						|| SqlInjectionScanCommand.DB_INSERT.matcher(line).find());
	}

	@Test
	void deleteWhereClauseConcatenationFires() {
		assertTrue(fires("db.delete(\"users\", \"id=\" + id, null);"),
				"a concatenated whereClause in delete() is a textbook SQL-injection carrier — must fire");
	}

	@Test
	void updateWhereClauseConcatenationFires() {
		assertTrue(fires("db.update(\"users\", cv, \"name='\" + name + \"'\", null);"),
				"a concatenated whereClause in update() is an injection carrier — must fire");
	}

	@Test
	void deleteWhereClauseStringFormatFires() {
		// The String.format form was missed because SQL_DYNAMIC_ARG did not list delete as a sink.
		assertTrue(fires("db.delete(\"users\", String.format(\"id=%s\", id), null);"),
				"a String.format whereClause in delete() must fire via the dynamic-arg path");
	}

	@Test
	void updateWhereClauseStringBuilderFires() {
		assertTrue(fires("db.update(\"t\", cv, new StringBuilder(\"id=\").append(id).toString(), null);"),
				"a StringBuilder whereClause in update() must fire via the dynamic-arg path");
	}

	@Test
	void insertTableConcatenationFires() {
		assertTrue(fires("db.insert(\"t_\" + suffix, null, cv);"),
				"a concatenated table name in insert() is medium-severity injection — must fire");
	}

	@Test
	void parameterizedDeleteDoesNotFire() {
		assertFalse(fires("db.delete(\"users\", \"id = ?\", new String[]{String.valueOf(id)});"),
				"a parameterized delete (whereClause uses ? + whereArgs) is safe — must not fire");
	}

	@Test
	void parameterizedUpdateDoesNotFire() {
		assertFalse(fires("db.update(\"users\", cv, \"name = ?\", new String[]{name});"),
				"a parameterized update is safe — must not fire");
	}

	@Test
	void staticInsertDoesNotFire() {
		assertFalse(fires("db.insert(\"users\", null, cv);"),
				"an insert with a static table name and ContentValues is safe — must not fire");
	}
}
