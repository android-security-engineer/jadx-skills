package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the cross-line path-traversal fix in {@link ExportedProviderScanCommand}.
 *
 * <p>Before the fix, {@code provider_path_traversal} required {@code FILE_SINK} and {@code URI_SOURCE}
 * on the <em>same</em> line. A real openFile implementation reads the path segment on one line and
 * builds the File on another, so the finding almost never fired. The fix matches {@code URI_SOURCE}
 * at class scope and keeps {@code FILE_SINK} as the per-line anchor; a canonical-path guard anywhere
 * in the class still suppresses it.
 */
class ExportedProviderPathTraversalTest {

	/** A realistic openFile: URI_SOURCE and FILE_SINK on different lines. */
	private static final String CROSS_LINE_CODE = String.join("\n",
			"public ParcelFileDescriptor openFile(Uri uri, String mode) {",
			"  String name = uri.getLastPathSegment();",
			"  File f = new File(getRoot(), name);",
			"  return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);",
			"}");

	/** Same shape but the class canonicalises the path — the documented fix, must suppress. */
	private static final String GUARDED_CODE = String.join("\n",
			"public ParcelFileDescriptor openFile(Uri uri, String mode) {",
			"  String name = uri.getLastPathSegment();",
			"  File f = new File(getRoot(), name);",
			"  String real = f.getCanonicalPath();",
			"  if (!real.startsWith(getRoot().getCanonicalPath())) throw new SecurityException();",
			"  return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);",
			"}");

	/** Class facts derived the same way execute() derives them, so the test mirrors real dispatch. */
	private static boolean classHasUriSource(String code) {
		return ExportedProviderScanCommand.URI_SOURCE.matcher(code).find();
	}

	private static boolean classGuardsPath(String code) {
		return ExportedProviderScanCommand.CANONICAL_GUARD.matcher(code).find();
	}

	private static boolean firesOnFileSinkLine(String code) {
		boolean hasUriSource = classHasUriSource(code);
		boolean guards = classGuardsPath(code);
		for (String line : code.split("\n", -1)) {
			if (ExportedProviderScanCommand.providerPathTraversalSignal(true, hasUriSource, guards, line)) {
				return true;
			}
		}
		return false;
	}

	@Test
	void crossLineUriSourceAndFileSinkNowFires() {
		assertTrue(firesOnFileSinkLine(CROSS_LINE_CODE),
				"a real openFile (URI source and File sink on different lines) must now be flagged");
	}

	@Test
	void canonicalGuardSuppressesEvenWhenCrossLine() {
		assertFalse(firesOnFileSinkLine(GUARDED_CODE),
				"a class that canonicalises the path is protected — no path-traversal finding");
	}

	@Test
	void signalRequiresOpenFileContext() {
		// No openFile in the class → classHasOpenFile false → must not fire even with File + URI.
		boolean hasUriSource = classHasUriSource(CROSS_LINE_CODE);
		boolean guards = classGuardsPath(CROSS_LINE_CODE);
		boolean any = false;
		for (String line : CROSS_LINE_CODE.split("\n", -1)) {
			if (ExportedProviderScanCommand.providerPathTraversalSignal(false, hasUriSource, guards, line)) {
				any = true;
			}
		}
		assertFalse(any, "without an openFile context this is ordinary file IO, not a provider sink");
	}

	@Test
	void sameLineFormStillFires() {
		// The pre-fix same-line form must still work (no regression).
		assertTrue(firesOnFileSinkLine("File f = new File(uri.getLastPathSegment());"));
	}

	@Test
	void noFileSinkNoFire() {
		String code = "String name = uri.getLastPathSegment();\nLog.i(\"x\", name);";
		assertFalse(firesOnFileSinkLine(code),
				"URI source without a File sink is not path traversal");
	}
}
