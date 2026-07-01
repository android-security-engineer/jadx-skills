package jadx.ai.cli.util;

import java.io.File;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the {@code .dynsym} parser ({@code nm -D} in pure Java) against the real
 * {@code lib/x86_64/libcode.so} in {@code resources-only.apk}. This is the ground-truth native
 * symbol surface that upgrades {@code native-lib-security} beyond its old {@code strings}-heuristic
 * guess — {@code .dynsym} survives {@code strip}, so exports/imports are recoverable on release libs.
 */
class ElfSymbolsTest {

	private static byte[] libcodeBytes() throws Exception {
		File apk = new File("../jadx-cli/src/test/resources/samples/resources-only.apk");
		assertTrue(apk.exists(), "fixture must exist: " + apk.getAbsolutePath());
		try (ZipFile zf = new ZipFile(apk)) {
			ZipEntry e = zf.getEntry("lib/x86_64/libcode.so");
			assertNotNull(e, "fixture must contain lib/x86_64/libcode.so");
			try (InputStream is = zf.getInputStream(e)) {
				return is.readAllBytes();
			}
		}
	}

	@Test
	void parsesDynsymOfRealLib() throws Exception {
		ElfSymbols s = ElfSymbols.parse(libcodeBytes(), 500);
		assertTrue(s.parsed, ".dynsym must be located and walked");
		assertTrue(s.is64, "libcode.so is x86_64");
		// A loadable lib must both define and import at least one symbol.
		assertTrue(s.exportedCount > 0, "must have exported symbols: " + s.exportedCount);
		assertTrue(s.importedCount > 0, "must import from its DT_NEEDED deps: " + s.importedCount);
		// Names must be real, printable identifiers (proves .dynstr resolution worked).
		for (String n : s.exported) {
			assertFalse(n.isBlank(), "export name must be non-blank");
		}
	}

	@Test
	void capBoundsCollectedNamesButNotCounts() throws Exception {
		byte[] d = libcodeBytes();
		ElfSymbols full = ElfSymbols.parse(d, 500);
		ElfSymbols capped = ElfSymbols.parse(d, 1);
		// counts are exact regardless of cap; collected lists are bounded by cap.
		assertTrue(capped.exportedCount == full.exportedCount, "counts must be cap-independent");
		assertTrue(capped.exported.size() <= 1, "collected exports must respect cap");
	}

	@Test
	void nonElfDoesNotThrow() {
		ElfSymbols s = ElfSymbols.parse(new byte[] { 0x4D, 0x5A, 0, 0 }, 100); // "MZ" PE stub
		assertFalse(s.parsed, "non-ELF must not report parsed");
		assertTrue(s.exported.isEmpty());
		assertTrue(s.imported.isEmpty());
	}
}
