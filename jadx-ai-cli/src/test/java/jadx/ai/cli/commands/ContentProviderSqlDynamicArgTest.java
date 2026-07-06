package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code sql_injection_provider} detection in {@link ContentProviderScanCommand} against
 * the sink+dynamic-arg asymmetry.
 *
 * <p>The old {@code SQL_CONCAT} was class-scope and matched {@code +} of operands literally named
 * {@code selection}/{@code sortOrder} OR any {@code rawQuery(}/{@code execSQL(} call. That was both
 * narrow (missed {@code String.format}/{@code StringBuilder}/{@code .concat} forms, and {@code +} of
 * any other operand name) and broad (flagged parameterized {@code rawQuery("...?", args)} as a false
 * positive). The detector now uses line-scope {@code SQL_SINK ∧ (CONCAT ∨ PROVIDER_SQL_DYNAMIC_ARG)},
 * mirroring {@code ExportedProviderScanCommand}'s already-symmetric form — covering every dynamic-
 * construction variant while leaving parameterized queries alone.
 */
class ContentProviderSqlDynamicArgTest {

	private static final Pattern SINK = ContentProviderScanCommand.SQL_SINK;
	private static final Pattern CONCAT = ContentProviderScanCommand.CONCAT;
	private static final Pattern DYN = ContentProviderScanCommand.PROVIDER_SQL_DYNAMIC_ARG;

	/** Mirrors execute()'s line-scope test: a SQL sink on a line that also builds its arg dynamically. */
	private static boolean fires(String line) {
		return SINK.matcher(line).find() && (CONCAT.matcher(line).find() || DYN.matcher(line).find());
	}

	@Test
	void selectionConcatFires() {
		assertTrue(fires("Cursor c = db.rawQuery(\"SELECT * FROM t WHERE \" + selection, null);"),
				"rawQuery + selection concat must fire (regression guard for the named-operand form)");
	}

	@Test
	void arbitraryOperandConcatFires() {
		assertTrue(fires("Cursor c = db.rawQuery(\"SELECT * FROM t WHERE id=\" + name, null);"),
				"rawQuery + concat of an operand NOT named selection/sortOrder must fire (the old rule missed this)");
	}

	@Test
	void stringFormatFires() {
		assertTrue(fires("Cursor c = db.rawQuery(String.format(\"SELECT * FROM t WHERE id=%s\", id), null);"),
				"rawQuery + String.format must fire — same CWE-89 class as + concat (the old rule missed this)");
	}

	@Test
	void stringBuilderAppendFires() {
		assertTrue(fires("db.execSQL(new StringBuilder().append(\"DELETE FROM t WHERE id=\").append(id).toString());"),
				"execSQL + StringBuilder.append must fire (the old rule missed this)");
	}

	@Test
	void concatMethodFires() {
		assertTrue(fires("db.rawQuery(\"SELECT * FROM t WHERE id=\".concat(id), null);"),
				"rawQuery + .concat must fire (the old rule missed this)");
	}

	@Test
	void appendWhereStringFormatFires() {
		assertTrue(fires("builder.appendWhere(String.format(\"name='%s'\", name));"),
				"appendWhere + String.format must fire — provider-SQLi sink");
	}

	@Test
	void parameterizedQueryDoesNotFire() {
		assertFalse(fires("Cursor c = db.rawQuery(\"SELECT * FROM t WHERE id=?\", selectionArgs);"),
				"a parameterized rawQuery (no dynamic construction) must NOT fire — the old class-scope rule false-positived this");
	}

	@Test
	void plainRawQueryNoArgDoesNotFire() {
		assertFalse(fires("Cursor c = db.rawQuery(\"SELECT * FROM t\", null);"),
				"a static rawQuery with no dynamic arg must NOT fire");
	}
}
