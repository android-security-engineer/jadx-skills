package jadx.ai.cli.commands;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the blutter-style engine-version extraction: the Dart snapshot stamp is recovered from a
 * binary buffer's ASCII strings, while a stray version-looking constant in Java shell code is only
 * trusted on a line that mentions "version".
 */
class FlutterVersionExtractTest {

	@Test
	void asciiStringsRecoversStampFromBinaryNoise() throws Exception {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		b.write(new byte[] { 0x7F, 'E', 'L', 'F', 0x00, 0x01, 0x02 });
		String stamp = "3.5.4 (stable) (Wed Oct 16 2024) on \"android_arm64\"";
		b.write(stamp.getBytes(StandardCharsets.US_ASCII));
		b.write(new byte[] { 0x00, 0x00 });

		String strings = FlutterAnalysisCommand.asciiStrings(b.toByteArray(), 6);
		assertTrue(strings.contains(stamp), "the embedded stamp must survive string extraction");

		java.util.regex.Matcher m =
				java.util.regex.Pattern.compile(
						"(\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.\\-]+)?)\\s+\\((stable|beta|dev|main|be)\\)\\s+\\(")
						.matcher(strings);
		assertTrue(m.find());
		assertEquals("3.5.4", m.group(1));
		assertEquals("stable", m.group(2));
	}

	@Test
	void versionFromJavaTrustsOnlyVersionLines() {
		String withVersion = "  String flutterVersion = \"3.19.6\";\n";
		assertEquals("Flutter 3.19.6", FlutterAnalysisCommand.versionFromJava(withVersion));
	}

	@Test
	void versionFromJavaIgnoresStrayConstants() {
		// A 3-dotted number with no "version" context must not be mistaken for the engine version.
		String noVersion = "  int[] table = {1, 2, 3};\n  rect.set(0.0f, 1.0f, 2.0f);\n";
		assertNull(FlutterAnalysisCommand.versionFromJava(noVersion));
	}
}
