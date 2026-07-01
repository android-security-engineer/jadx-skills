package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the ContentProvider CRUD / openFile method-signature anchors in
 * {@link ContentProviderScanCommand} against jadx's modifier echo.
 *
 * <p>jadx echoes {@code final}/{@code synchronized}/{@code static} method modifiers
 * (AccessInfo.makeString, between {@code public} and the return type). A provider that seals or
 * locks its CRUD methods — {@code public final Uri insert(...)} / {@code public synchronized Cursor
 * query(...)} — is common, and the bare {@code public\s+ReturnType\s+methodName} form missed it, so
 * the method went unrecognised and {@code unvalidated_insert} / {@code sql_injection_provider} /
 * etc. were silently dropped. Unlike DataResidueScan / ExportedProviderScan, this command has NO
 * {@code extends ContentProvider} fallback for method recognition — the signature regex IS the only
 * signal — so the miss is fatal here.
 */
class ContentProviderMethodSignatureModifierTest {

	private static boolean queries(String line) {
		return ContentProviderScanCommand.QUERY_METHOD.matcher(line).find();
	}

	private static boolean inserts(String line) {
		return ContentProviderScanCommand.INSERT_METHOD.matcher(line).find();
	}

	private static boolean updates(String line) {
		return ContentProviderScanCommand.UPDATE_METHOD.matcher(line).find();
	}

	private static boolean deletes(String line) {
		return ContentProviderScanCommand.DELETE_METHOD.matcher(line).find();
	}

	private static boolean opensFile(String line) {
		return ContentProviderScanCommand.OPEN_FILE_METHOD.matcher(line).find();
	}

	@Test
	void plainSignaturesStillMatch() {
		assertTrue(queries("public Cursor query(Uri uri, String[] projection) {"),
				"plain public Cursor query must match (regression guard)");
		assertTrue(inserts("public Uri insert(Uri uri, ContentValues values) {"),
				"plain public Uri insert must match (regression guard)");
		assertTrue(updates("public int update(Uri uri, ContentValues values, String selection) {"),
				"plain public int update must match (regression guard)");
		assertTrue(deletes("public int delete(Uri uri, String selection) {"),
				"plain public int delete must match (regression guard)");
		assertTrue(opensFile("public ParcelFileDescriptor openFile(Uri uri, String mode) {"),
				"plain public ParcelFileDescriptor openFile must match (regression guard)");
	}

	@Test
	void finalModifierMatches() {
		assertTrue(queries("public final Cursor query(Uri uri, String[] p) {"),
				"public final Cursor query (jadx echoes final) must match");
		assertTrue(inserts("public final Uri insert(Uri uri, ContentValues v) {"),
				"public final Uri insert must match");
		assertTrue(updates("public final int update(Uri uri, ContentValues v, String s) {"),
				"public final int update must match");
		assertTrue(deletes("public final int delete(Uri uri, String s) {"),
				"public final int delete must match");
		assertTrue(opensFile("public final ParcelFileDescriptor openFile(Uri uri, String m) {"),
				"public final ParcelFileDescriptor openFile must match");
	}

	@Test
	void synchronizedModifierMatches() {
		assertTrue(queries("public synchronized Cursor query(Uri uri, String[] p) {"),
				"public synchronized Cursor query (jadx echoes synchronized) must match");
		assertTrue(inserts("public synchronized Uri insert(Uri uri, ContentValues v) {"),
				"public synchronized Uri insert must match");
	}

	@Test
	void staticModifierMatches() {
		assertTrue(queries("public static Cursor query(Uri uri) {"),
				"public static Cursor query (jadx echoes static) must match");
	}

	@Test
	void finalPlusSynchronizedMatches() {
		assertTrue(queries("public final synchronized Cursor query(Uri uri) {"),
				"public final synchronized Cursor query (modifier combo) must match");
	}

	@Test
	void nonProviderMethodDoesNotMatch() {
		assertFalse(queries("public Cursor getCursor() {"),
				"a non-query Cursor method must not match the query signature");
		assertFalse(inserts("public Uri buildUri() {"),
				"a non-insert Uri method must not match the insert signature");
		assertFalse(deletes("public int count() {"),
				"a non-delete int method must not match the delete signature");
	}
}
