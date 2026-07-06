package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code external_data_sql} detection in {@link TrustBoundaryScanCommand}.
 *
 * <p>The same-line AND ({@code getIntent.*rawQuery|...}) missed the common jadx-decompiled form:
 * jadx emits the Intent-extra extraction and the SQL sink on <b>separate lines</b> —
 * {@code String n = getIntent().getStringExtra("n");} then {@code db.rawQuery("..." + n, null);}.
 * The detector now pairs a class-scope IPC source ({@link #IPC_SOURCE}) with a line-scope SQL
 * sink ({@link #EXTERNAL_DATA_SQL_SINK}), mirroring ExportedProviderScan / PathTraversal.
 *
 * <p>This test asserts the two package-private Patterns directly (no re-compiled regex),
 * covering: cross-line fire, parameterized-query suppression, IPC-source-absent suppression,
 * and sink-absent suppression.
 */
class TrustBoundaryExternalDataSqlTest {

	private static final Pattern IPC_SOURCE = TrustBoundaryScanCommand.IPC_SOURCE;
	private static final Pattern SQL_SINK = TrustBoundaryScanCommand.EXTERNAL_DATA_SQL_SINK;

	/** Mirrors execute()'s cross-line test: class has an IPC source ∧ some line has a SQL sink. */
	private static boolean injectable(String code) {
		if (!IPC_SOURCE.matcher(code).find()) {
			return false;
		}
		for (String line : code.split("\n", -1)) {
			if (SQL_SINK.matcher(line).find()) {
				return true;
			}
		}
		return false;
	}

	@Test
	void intentExtraIntoRawQueryAcrossLinesFires() {
		assertTrue(injectable("String name = getIntent().getStringExtra(\"name\");\n"
				+ "Cursor c = db.rawQuery(\"SELECT * FROM users WHERE n='\" + name + \"'\", null);"),
				"Intent extra on one line flowing into rawQuery on another must fire — the common jadx form");
	}

	@Test
	void bundleExtraIntoExecSqlAcrossLinesFires() {
		assertTrue(injectable("Bundle b = getIntent().getExtras();\n"
				+ "String id = b.getString(\"id\");\n"
				+ "db.execSQL(\"DELETE FROM t WHERE id=\" + id);"),
				"Bundle-derived data flowing into execSQL across lines must fire");
	}

	@Test
	void getIntentIntoInsertDoesNotFire() {
		// db.insert(table, nullColumnHack, ContentValues) is the parameterized/ContentValues API —
		// SAFE by construction (no string concatenation into SQL). The old sink matched .insert and
		// flagged this high; the tightened sink requires a literal SQL + concatenation, so it no
		// longer fires. (Intent extra persistence is a separate data-flow concern, not SQL injection.)
		assertFalse(injectable("String user = getIntent().getStringExtra(\"user\");\n"
				+ "db.insert(\"users\", null, cv);"),
				"Intent extra then db.insert (ContentValues — SAFE) must NOT fire SQL injection");
	}

	@Test
	void parameterizedQueryDoesNotFire() {
		// selectionArgs — the correct pattern. The tightened sink requires a literal SQL concatenated
		// with `+`; a parameterized rawQuery("...=?", selectionArgs) has no concatenation, so it does
		// NOT fire — even with an Intent extra in scope. This is the desired behavior: the sink regex
		// now distinguishes the injection shape from the parameterized shape.
		assertFalse(injectable("String name = getIntent().getStringExtra(\"name\");\n"
				+ "Cursor c = db.rawQuery(\"SELECT * FROM users WHERE n=?\", new String[]{name});"),
				"a parameterized rawQuery (no string concatenation) must NOT fire — the tightened "
						+ "sink distinguishes injection from parameterization");
	}

	@Test
	void sqlSinkWithoutIpcSourceDoesNotFire() {
		assertFalse(injectable("String name = hardCodedName();\n"
				+ "db.rawQuery(\"SELECT * FROM users WHERE n='\" + name + \"'\", null);"),
				"a SQL sink with no Intent/Bundle source in the class must NOT fire — no untrusted input");
	}

	@Test
	void ipcSourceWithoutSqlSinkDoesNotFire() {
		assertFalse(injectable("String name = getIntent().getStringExtra(\"name\");\n"
				+ "textView.setText(name);"),
				"an Intent extra with no SQL sink in the class must NOT fire — source never reaches a SQL sink");
	}
}
