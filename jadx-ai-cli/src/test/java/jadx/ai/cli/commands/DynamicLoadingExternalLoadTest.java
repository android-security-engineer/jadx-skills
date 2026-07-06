package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the cross-line {@code external_dex_load}/{@code external_native_load} fix in
 * {@link DynamicLoadingScanCommand}.
 *
 * <p>The high-severity external-load signal used to require the code loader ({@code DexClassLoader}/
 * {@code System.load}) and an attacker-influenceable source ({@code getExternalFilesDir},
 * {@code /sdcard}, {@code http(s)://}) on the <b>same</b> line. But jadx decompiles a real plugin
 * loader with the source on one line ({@code File dex = new File(getExternalFilesDir(null), "p.dex");})
 * and the loader on another ({@code new DexClassLoader(dex.getPath(), ...);}) — so the high RCE
 * finding was systematically degraded to {@code dynamic_dex_load}/{@code native_load_path} medium.
 * Fixed with the {@link ExportedProviderScanCommand}/{@link InsecureDeeplinkHandlerScanCommand}
 * pattern: class-scoped {@code EXTERNAL_SRC} ∧ per-line loader anchor.
 *
 * <p>{@code execute()} decides high vs medium with {@code classHasExternalSrc || EXTERNAL_SRC.matcher(line).find()}.
 * {@code classHasExternalSrc} is the cross-line fix; the {@code || EXTERNAL_SRC.matcher(line)} term is the
 * same-line regression guard. {@link DynamicLoadingScanCommand#externalLoadSignal} captures the class-level
 * half, so these tests drive it with the class-level source computed from synthetic code and the loader line.
 */
class DynamicLoadingExternalLoadTest {

	/** The class-level external-source flag, exactly as execute() computes it. */
	private static boolean classHasExternalSrc(String code) {
		return DynamicLoadingScanCommand.EXTERNAL_SRC.matcher(code).find();
	}

	@Test
	void crossLineExternalDexFiresHigh() {
		// The real jadx form: external path on line N, DexClassLoader on line N+1.
		String code = "File dex = new File(getExternalFilesDir(null), \"plugin.dex\");\n"
				+ "DexClassLoader cl = new DexClassLoader(dex.getPath(), odexDir, null, classLoader);";
		assertTrue(DynamicLoadingScanCommand.externalLoadSignal(classHasExternalSrc(code),
						"DexClassLoader cl = new DexClassLoader(dex.getPath(), odexDir, null, classLoader);"),
				"a class that reads external storage and constructs a DexClassLoader on another line must fire high");
	}

	@Test
	void sameLineExternalDexStillFiresHigh() {
		// Regression guard: the inlined same-line form. The loader line itself carries the source,
		// so execute()'s `|| EXTERNAL_SRC.matcher(line)` term fires it; externalLoadSignal with the
		// class-level flag also fires because the whole-code block contains the source.
		String code = "new DexClassLoader(getExternalFilesDir(null).getAbsolutePath(), odex, null, cl);";
		assertTrue(DynamicLoadingScanCommand.externalLoadSignal(classHasExternalSrc(code), code),
				"the inlined same-line external DexClassLoader form must still fire high");
	}

	@Test
	void dexLoaderWithoutExternalSourceStaysMedium() {
		// A DexClassLoader with no class-level external source (app-private / hardcoded path) is medium.
		String code = "DexClassLoader cl = new DexClassLoader(appDir + \"/o.dex\", odex, null, cl);";
		assertFalse(DynamicLoadingScanCommand.externalLoadSignal(classHasExternalSrc(code),
						"DexClassLoader cl = new DexClassLoader(appDir + \"/o.dex\", odex, null, cl);"),
				"a DexClassLoader with no external/network source must NOT fire the high external signal");
	}

	@Test
	void crossLineNativeLoadFiresHigh() {
		// System.load of a .so resolved from external storage on another line.
		String code = "String soPath = getExternalStorageDirectory() + \"/lib/libpayload.so\";\n"
				+ "System.load(soPath);";
		assertTrue(DynamicLoadingScanCommand.externalLoadSignal(classHasExternalSrc(code),
						"System.load(soPath);"),
				"a System.load fed by an external-storage path on another line must fire high");
	}

	@Test
	void networkUrlSourceFiresHigh() {
		// A download URL anywhere in the class makes a DexClassLoader an external load.
		String code = "String url = \"https://cdn.example.com/payload.dex\";\n"
				+ "DexClassLoader cl = new DexClassLoader(downloadedPath, odex, null, cl);";
		assertTrue(DynamicLoadingScanCommand.externalLoadSignal(classHasExternalSrc(code),
						"DexClassLoader cl = new DexClassLoader(downloadedPath, odex, null, cl);"),
				"a class with a network URL and a DexClassLoader must fire high");
	}

	@Test
	void externalStorageWithoutLoaderDoesNotFire() {
		// A class that merely reads external storage but loads nothing is not a dynamic-loading risk.
		String code = "File log = new File(getExternalFilesDir(null), \"log.txt\");\n"
				+ "FileOutputStream fos = new FileOutputStream(log);";
		assertFalse(DynamicLoadingScanCommand.externalLoadSignal(classHasExternalSrc(code),
						"FileOutputStream fos = new FileOutputStream(log);"),
				"external storage with no code loader must not fire the external-load signal");
	}

	@Test
	void sdcardLiteralSourceFiresHigh() {
		// The /sdcard literal shorthand as the external source.
		String code = "String p = \"/sdcard/Download/plugin.dex\";\n"
				+ "DexFile.loadDex(p, odex, 0);";
		assertTrue(DynamicLoadingScanCommand.externalLoadSignal(classHasExternalSrc(code),
						"DexFile.loadDex(p, odex, 0);"),
				"a /sdcard path feeding DexFile.loadDex must fire high");
	}

	@Test
	void systemLoadLibraryDoesNotFire() {
		// System.loadLibrary("name") is the normal, non-path native load — not matched by NATIVE_LOAD_PATH,
		// so externalLoadSignal returns false even with an external source present.
		String code = "String dir = getExternalFilesDir(null) + \"/lib\";\n"
				+ "System.loadLibrary(\"native-lib\");";
		assertFalse(DynamicLoadingScanCommand.externalLoadSignal(classHasExternalSrc(code),
						"System.loadLibrary(\"native-lib\");"),
				"System.loadLibrary is the normal native load and must not fire the path-load signal");
	}
}
