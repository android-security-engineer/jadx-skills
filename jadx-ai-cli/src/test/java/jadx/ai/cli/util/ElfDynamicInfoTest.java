package jadx.ai.cli.util;

import java.io.File;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Directly exercises the ELF {@code .dynamic} parser against the real {@code lib/x86_64/libcode.so}
 * bundled in the {@code resources-only.apk} fixture — the {@code readelf -d} ground truth that
 * {@code native-lib-security} now surfaces (DT_NEEDED deps, SONAME, BIND_NOW → full/partial RELRO).
 */
class ElfDynamicInfoTest {

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
	void parsesDynamicSegmentOfRealLib() throws Exception {
		ElfDynamicInfo info = ElfDynamicInfo.parse(libcodeBytes());
		assertTrue(info.parsed, "PT_DYNAMIC must be found and walked");
		assertTrue(info.is64, "libcode.so is x86_64");
		assertTrue(info.needed.contains("libc.so"), "DT_NEEDED must include libc.so: " + info.needed);
		assertEquals("libcode.so", info.soname, "DT_SONAME");
	}

	@Test
	void reportsFullVsPartialRelro() throws Exception {
		ElfDynamicInfo info = ElfDynamicInfo.parse(libcodeBytes());
		// A GNU_RELRO segment IS present in this lib; whether it is full depends on BIND_NOW.
		String withSegment = info.relroType(true);
		assertTrue(withSegment.equals("full") || withSegment.equals("partial"),
				"relro with segment must be full|partial, got " + withSegment);
		assertEquals("none", info.relroType(false), "no segment => none");
	}

	@Test
	void nonElfInputDoesNotThrow() {
		ElfDynamicInfo info = ElfDynamicInfo.parse(new byte[] { 0x4D, 0x5A, 0, 0 }); // "MZ" (PE), too short
		assertFalse(info.parsed, "non-ELF must not report parsed");
		assertTrue(info.needed.isEmpty());
	}
}
