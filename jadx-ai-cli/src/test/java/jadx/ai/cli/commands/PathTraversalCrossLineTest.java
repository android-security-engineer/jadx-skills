package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the cross-line {@code path_traversal} fix in {@link PathTraversalScanCommand}.
 *
 * <p>{@code path_traversal} required a file sink ({@code new File}/FileInputStream/...) and an
 * untrusted source ({@code getStringExtra}/{@code getQueryParameter}/{@code Uri.parse}/...) on the
 * SAME line. jadx decompiles a real handler with the source on line N
 * ({@code String p = intent.getStringExtra("path")}) and the sink on line N+1 ({@code new File(p)}),
 * so the high-severity finding was systematically missed. Fixed with the deeplink/exported-provider
 * pattern: class-scoped {@code UNTRUSTED} ∧ per-line {@code FILE_SINK} anchor, suppressed by a
 * class-scoped canonical guard.
 */
class PathTraversalCrossLineTest {

	/** Mirrors execute()'s per-class decision for path_traversal. */
	private static boolean fires(String code, String line) {
		boolean classHasUntrusted = PathTraversalScanCommand.UNTRUSTED.matcher(code).find();
		boolean classGuardsPath = PathTraversalScanCommand.CANONICAL_GUARD.matcher(code).find();
		return PathTraversalScanCommand.untrustedPathSignal(classHasUntrusted, classGuardsPath, line);
	}

	@Test
	void crossLineSourceAndSinkFires() {
		// The real jadx form: untrusted source on line N, file sink on line N+1.
		String code = "String path = intent.getStringExtra(\"file\");\n"
				+ "File f = new File(path);";
		assertTrue(fires(code, "File f = new File(path);"),
				"an intent extra read on one line and a File opened on another must fire");
	}

	@Test
	void sameLineFormStillFires() {
		// Regression guard: the inlined same-line form must still fire.
		String code = "File f = new File(intent.getStringExtra(\"file\"));";
		assertTrue(fires(code, code),
				"the inlined same-line source+sink form must still fire");
	}

	@Test
	void uriParseSourceFires() {
		String code = "Uri uri = Uri.parse(getIntent().getData().toString());\n"
				+ "String seg = uri.getLastPathSegment();\n"
				+ "FileInputStream fis = new FileInputStream(seg);";
		assertTrue(fires(code, "FileInputStream fis = new FileInputStream(seg);"),
				"Uri.parse + getLastPathSegment feeding a FileInputStream must fire cross-line");
	}

	@Test
	void canonicalGuardSuppresses() {
		String code = "String path = intent.getStringExtra(\"file\");\n"
				+ "File base = getFilesDir();\n"
				+ "File f = new File(base, path);\n"
				+ "if (!f.getCanonicalPath().startsWith(base.getCanonicalPath())) throw new SecurityException();";
		assertFalse(fires(code, "File f = new File(base, path);"),
				"a class that canonicalizes + startsWith-checks defends against traversal — no finding");
	}

	@Test
	void noUntrustedSourceDoesNotFire() {
		// A class that opens a static File but never reads untrusted input is not path traversal.
		String code = "File f = new File(getFilesDir(), \"const.txt\");";
		assertFalse(fires(code, "File f = new File(getFilesDir(), \"const.txt\");"),
				"without an untrusted source, a static file open is not path_traversal");
	}

	@Test
	void noFileSinkDoesNotFire() {
		String code = "String path = intent.getStringExtra(\"file\");\n"
				+ "Log.d(TAG, \"path=\" + path);";
		assertFalse(fires(code, "Log.d(TAG, \"path=\" + path);"),
				"an untrusted source without a file sink is not path traversal");
	}

	@Test
	void queryParameterSourceFires() {
		String code = "String name = uri.getQueryParameter(\"name\");\n"
				+ "FileWriter fw = new FileWriter(name);";
		assertTrue(fires(code, "FileWriter fw = new FileWriter(name);"),
				"getQueryParameter as the source must fire on a cross-line file sink");
	}
}
