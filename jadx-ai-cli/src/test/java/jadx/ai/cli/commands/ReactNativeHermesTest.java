package jadx.ai.cli.commands;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the React Native bundle triage: the Hermes Bytecode File magic is matched from the raw
 * little-endian header, the bytecode version is read from offset 8, a plaintext JS bundle is NOT
 * mistaken for Hermes, and URLs/strings are recovered from bundle bytes.
 */
class ReactNativeHermesTest {

	/** Build a minimal Hermes header: magic (LE) + version uint32 (LE) + padding. */
	private static byte[] hermesHeader(int version) throws Exception {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		// 0x1F1903C103BC1FC6 little-endian on disk.
		b.write(new byte[] {
				(byte) 0xC6, (byte) 0x1F, (byte) 0xBC, 0x03,
				(byte) 0xC1, 0x03, 0x19, 0x1F });
		// version uint32 LE at offset 8
		b.write(new byte[] { (byte) (version & 0xFF), (byte) ((version >> 8) & 0xFF),
				(byte) ((version >> 16) & 0xFF), (byte) ((version >> 24) & 0xFF) });
		// pad out past the string-count field (offset 52) so readU32 calls are in range
		b.write(new byte[64]);
		return b.toByteArray();
	}

	@Test
	void detectsHermesMagicAndVersion() throws Exception {
		byte[] head = hermesHeader(96);
		assertTrue(ReactNativeAnalysisCommand.isHermesBytecode(head), "Hermes magic must be recognized");
		assertEquals(96L, ReactNativeAnalysisCommand.hermesBytecodeVersion(head));
	}

	@Test
	void plaintextJsIsNotHermes() {
		byte[] js = "var x=1;require('react-native');__d(function(){});".getBytes(StandardCharsets.UTF_8);
		assertFalse(ReactNativeAnalysisCommand.isHermesBytecode(js),
				"a plaintext JS bundle must not be misclassified as Hermes bytecode");
	}

	@Test
	void tooShortBufferIsNotHermes() {
		assertFalse(ReactNativeAnalysisCommand.isHermesBytecode(new byte[] { 0x00, 0x01 }));
	}

	@Test
	void extractsDistinctUrlsInOrder() {
		String text = "fetch('https://api.example.com/v1');img='http://cdn.test/x.png';again='https://api.example.com/v1'";
		List<String> urls = ReactNativeAnalysisCommand.extractUrls(text, 200);
		assertEquals(2, urls.size(), "duplicate URLs must be collapsed");
		assertEquals("https://api.example.com/v1", urls.get(0));
		assertTrue(urls.contains("http://cdn.test/x.png"));
	}

	@Test
	void asciiStringsRecoversUrlFromBinaryNoise() throws Exception {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		b.write(new byte[] { (byte) 0xC6, 0x00, (byte) 0xFF, 0x01 });
		b.write("https://secret.internal/api".getBytes(StandardCharsets.US_ASCII));
		b.write(new byte[] { 0x00, 0x00 });
		String strings = ReactNativeAnalysisCommand.asciiStrings(b.toByteArray(), 5);
		assertTrue(strings.contains("https://secret.internal/api"),
				"an embedded URL must survive Hermes string extraction");
	}
}
