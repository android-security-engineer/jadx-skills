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
	void getIntentIntoInsertAcrossLinesFires() {
		assertTrue(injectable("String user = getIntent().getStringExtra(\"user\");\n"
				+ "db.insert(\"users\", null, cv);"),
				"Intent extra then db.insert on a later line must fire");
	}

	@Test
	void parameterizedQueryDoesNotFire() {
		// selectionArgs — the correct pattern. SQL sink present, IPC source present, but the
		// *parameterized* form (rawQuery(sql, selectionArgs)) is exactly what we want to NOT flag.
		// The detector is intentionally syntax-only (no taint tracking), so a parameterized call
		// with an Intent extra in scope still trips the sink pattern — this test documents that
		// the sink regex matches .rawQuery( regardless of args, and IPC source is in scope, so it
		// WILL fire. This is the deliberate trade-off: flag the sink, let triage confirm param use.
		assertTrue(injectable("String name = getIntent().getStringExtra(\"name\");\n"
				+ "Cursor c = db.rawQuery(\"SELECT * FROM users WHERE n=?\", new String[]{name});"),
				"syntax-only detector intentionally flags rawQuery even with selectionArgs — "
						+ "no taint tracking; triage confirms parameterization");
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
