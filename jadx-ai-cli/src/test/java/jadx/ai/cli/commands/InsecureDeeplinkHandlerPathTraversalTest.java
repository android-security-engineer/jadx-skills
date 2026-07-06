package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the cross-line {@code deeplink_path_traversal} fix in {@link InsecureDeeplinkHandlerScanCommand}.
 *
 * <p>{@code PATH_TRAVERSAL} used a single-line {@code .*} AND ({@code getData.*File\(|getPath.*File\(|...}),
 * but jadx decompiles a real deep-link handler with the URI source ({@code getData()}/
 * {@code getQueryParameter()}/{@code getPath()}) and the file sink ({@code new File}/
 * {@code FileInputStream}) on different lines, so the high-severity finding was systematically missed.
 * Fixed with the {@link ExportedProviderScanCommand} pattern: class-scoped {@code DEEPLINK_SOURCE} ∧
 * per-line {@code FILE_SINK} anchor, suppressed by a class-scoped canonical-path guard.
 */
class InsecureDeeplinkHandlerPathTraversalTest {

	/** Mirrors execute()'s per-line decision for deeplink_path_traversal. */
	private static boolean fires(String code, String line) {
		boolean classHasSource = InsecureDeeplinkHandlerScanCommand.DEEPLINK_SOURCE.matcher(code).find();
		boolean classGuardsPath = InsecureDeeplinkHandlerScanCommand.DEEPLINK_CANONICAL_GUARD.matcher(code).find();
		return InsecureDeeplinkHandlerScanCommand.deeplinkPathTraversalSignal(classHasSource, classGuardsPath, line);
	}

	@Test
	void crossLineSourceAndSinkFires() {
		// The real jadx form: source on line N, file sink on line N+2.
		String code = "Uri data = getIntent().getData();\n"
				+ "String path = data.getPath();\n"
				+ "FileInputStream fis = new FileInputStream(path);";
		assertTrue(fires(code, "FileInputStream fis = new FileInputStream(path);"),
				"a deep-link URI read on one line and a file opened on another must fire");
	}

	@Test
	void sameLineFormStillFires() {
		// Regression guard: the inlined same-line form must still fire.
		String code = "FileInputStream fis = new FileInputStream(getIntent().getData().getPath());";
		assertTrue(fires(code, code),
				"the inlined same-line source+sink form must still fire");
	}

	@Test
	void getQueryParameterSourceFires() {
		String code = "String name = uri.getQueryParameter(\"file\");\n"
				+ "File f = new File(name);";
		assertTrue(fires(code, "File f = new File(name);"),
				"getQueryParameter as the deep-link source must also trigger on a cross-line file sink");
	}

	@Test
	void canonicalGuardSuppresses() {
		String code = "Uri data = getIntent().getData();\n"
				+ "String path = data.getPath();\n"
				+ "String safe = new File(path).getCanonicalPath();\n"
				+ "FileInputStream fis = new FileInputStream(safe);";
		assertFalse(fires(code, "FileInputStream fis = new FileInputStream(safe);"),
				"a class that canonicalizes paths defends against traversal — no finding");
	}

	@Test
	void noDeepLinkSourceDoesNotFire() {
		// A class that opens a static File but never reads a deep-link URI is not a deep-link traversal.
		String code = "File f = new File(\"/data/local/tmp/const\");";
		assertFalse(fires(code, "File f = new File(\"/data/local/tmp/const\");"),
				"without a deep-link URI source, a static file open is not deeplink_path_traversal");
	}

	@Test
	void noFileSinkDoesNotFire() {
		String code = "Uri data = getIntent().getData();\n"
				+ "String host = data.getHost();";
		assertFalse(fires(code, "String host = data.getHost();"),
				"a deep-link source without a file sink is not path traversal");
	}

	@Test
	void openFileSinkFires() {
		String code = "Uri data = getIntent().getData();\n"
				+ "ParcelFileDescriptor pfd = openFile(data, \"r\");";
		assertTrue(fires(code, "ParcelFileDescriptor pfd = openFile(data, \"r\");"),
				"openFile() is a file sink — must fire with a deep-link source");
	}
}
