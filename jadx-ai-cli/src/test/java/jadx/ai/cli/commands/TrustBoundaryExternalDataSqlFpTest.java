package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the false-positive fix in {@link TrustBoundaryScanCommand#EXTERNAL_DATA_SQL_SINK}.
 *
 * <p>The old sink matched {@code .query/.insert/.update/.delete} — the parameterized (ContentValues
 * + selectionArgs) APIs that are SAFE by construction — so every normal database class that reads an
 * Intent extra and writes it via {@code db.insert(...)} was flagged {@code external_data_sql}
 * <b>high</b>. Now restricted to {@code rawQuery}/{@code execSQL}/{@code compileStatement} AND
 * requires a string-literal SQL concatenated with {@code +}. Verified against real
 * javac&#8594;d8&#8594;jadx output.
 */
class TrustBoundaryExternalDataSqlFpTest {

	private static final java.util.regex.Pattern SINK = TrustBoundaryScanCommand.EXTERNAL_DATA_SQL_SINK;

	// --- false positives: parameterized / safe calls must NOT fire ---

	@Test
	void insertDoesNotFire() {
		assertFalse(SINK.matcher("        sQLiteDatabase.insert(\"users\", null, contentValues);").find(),
				"db.insert(...) uses ContentValues — SAFE, must NOT fire (was a high FP)");
	}

	@Test
	void queryWithSelectionArgsDoesNotFire() {
		assertFalse(SINK.matcher(
				"        sQLiteDatabase.query(\"users\", null, \"name=?\", new String[]{name}, null, null, null);").find(),
				"db.query with selectionArgs — SAFE, must NOT fire");
	}

	@Test
	void updateDoesNotFire() {
		assertFalse(SINK.matcher("        db.update(\"users\", cv, \"id=?\", args);").find(),
				"db.update with selectionArgs — SAFE, must NOT fire");
	}

	@Test
	void rawQueryParameterizedDoesNotFire() {
		assertFalse(SINK.matcher("        db.rawQuery(\"SELECT * FROM t WHERE id=?\", new String[]{id});").find(),
				"a parameterized rawQuery (no concatenation) must NOT fire");
	}

	// --- true positives: injection shape (literal SQL + concatenation) ---

	@Test
	void rawQueryWithConcatFires() {
		assertTrue(SINK.matcher(
				"        sQLiteDatabase.rawQuery(\"SELECT * FROM users WHERE name='\" + getIntent().getStringExtra(\"name\") + \"'\", null);").find(),
				"rawQuery with string concatenation — the real injection shape — must fire");
	}

	@Test
	void execSqlWithConcatFires() {
		assertTrue(SINK.matcher("        db.execSQL(\"DELETE FROM t WHERE id=\" + id);").find(),
				"execSQL with string concatenation must fire");
	}

	@Test
	void compileStatementWithConcatFires() {
		assertTrue(SINK.matcher("        db.compileStatement(\"INSERT INTO t VALUES(\" + v + \")\");").find(),
				"compileStatement with string concatenation must fire");
	}
}
