package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code content_provider_residue} implementation in {@link DataResidueScanCommand}.
 *
 * <p>The class doc promised a {@code content_provider_residue} finding — "ContentProvider with
 * insert/update but no delete — data added to provider is never cleaned up on uninstall" — but
 * {@code RULES} never emitted it (the {@code RESIDUE_MARKER} gate even included
 * {@code insert|update|delete} but no rule consumed them). Same defect class as the
 * {@code flag_secure_absent} finding {@code ScreenCaptureScanCommand} had this session: promised in
 * the doc, never emitted. The fix: flag a ContentProvider class that writes (insert/update) but
 * never deletes.
 */
class DataResidueContentProviderResidueTest {

	@Test
	void providerWithInsertButNoDeleteFires() {
		String code = "public class FriendsProvider extends ContentProvider {\n"
				+ "  public Uri insert(Uri uri, ContentValues v) { return insertRow(uri, v); }\n"
				+ "  public Cursor query(Uri uri, String[] p, String s, String[] a, String g) { return null; }\n"
				+ "}";
		assertTrue(DataResidueScanCommand.contentProviderResidueSignal(code),
				"a ContentProvider with insert and no delete leaves residue on uninstall");
	}

	@Test
	void providerWithUpdateButNoDeleteFires() {
		String code = "public class SettingsProvider extends ContentProvider {\n"
				+ "  public int update(Uri uri, ContentValues v, String s, String[] a) { return 1; }\n"
				+ "}";
		assertTrue(DataResidueScanCommand.contentProviderResidueSignal(code),
				"a ContentProvider with update and no delete also leaves residue");
	}

	@Test
	void providerWithInsertAndDeleteDoesNotFire() {
		// delete() present means the provider cleans up — no residue signal.
		String code = "public class MsgProvider extends ContentProvider {\n"
				+ "  public Uri insert(Uri uri, ContentValues v) { return null; }\n"
				+ "  public int delete(Uri uri, String s, String[] a) { return 1; }\n"
				+ "}";
		assertFalse(DataResidueScanCommand.contentProviderResidueSignal(code),
				"a provider that implements delete() cleans up — no residue");
	}

	@Test
	void providerWithOnlyQueryDoesNotFire() {
		// A read-only provider (no insert/update) writes nothing — no residue.
		String code = "public class ReadOnlyProvider extends ContentProvider {\n"
				+ "  public Cursor query(Uri uri, String[] p, String s, String[] a, String g) { return null; }\n"
				+ "  public String getType(Uri uri) { return null; }\n"
				+ "}";
		assertFalse(DataResidueScanCommand.contentProviderResidueSignal(code),
				"a read-only provider writes nothing — no residue");
	}

	@Test
	void nonProviderClassWithInsertDoesNotFire() {
		// An SQLiteDatabase call site that inserts but doesn't delete is NOT a provider — must not fire.
		String code = "public class DbHelper {\n"
				+ "  void add(String v) { db.insert(\"t\", null, cv); }\n"
				+ "}";
		assertFalse(DataResidueScanCommand.contentProviderResidueSignal(code),
				"insert/update without a ContentProvider context is not provider residue");
	}

	@Test
	void providerWithMethodSignatureFormFires() {
		// No 'extends ContentProvider' but the canonical insert(Uri,...) signature marks a provider.
		String code = "public class P {\n"
				+ "  public Uri insert(Uri uri, ContentValues v) { return null; }\n"
				+ "  public Cursor query(Uri uri, String[] p, String s, String[] a, String g) { return null; }\n"
				+ "}";
		assertTrue(DataResidueScanCommand.contentProviderResidueSignal(code),
				"the insert(Uri,...) ContentProvider signature marks the class as a provider");
	}

	@Test
	void emptyOrNullCodeDoesNotFire() {
		assertFalse(DataResidueScanCommand.contentProviderResidueSignal(""));
		assertFalse(DataResidueScanCommand.contentProviderResidueSignal(null));
	}
}
