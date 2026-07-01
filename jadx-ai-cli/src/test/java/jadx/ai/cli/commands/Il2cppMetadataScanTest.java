package jadx.ai.cli.commands;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import picocli.CommandLine;

import jadx.ai.cli.JadxAICLI;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the binary-read fix for {@code il2cpp-metadata-scan}. {@code global-metadata.dat} is a
 * binary file whose magic (0xFAB11BAF) contains non-ASCII bytes; the old code read it through
 * {@code loadContent().getText()} which lossily text-decoded the bytes and corrupted every offset,
 * so the magic check ALWAYS failed. The fix reads raw bytes via {@code ResourcesLoader.decodeStream}.
 * This test synthesises a minimal metadata blob, injects it into an APK, and asserts the C# names
 * are actually recovered — which is only possible if the bytes survive intact.
 */
class Il2cppMetadataScanTest {

	private static byte[] synthMetadata() {
		byte[] buf = new byte[256];
		putLe(buf, 0, 0xFAB11BAF);      // magic
		putLe(buf, 4, 29);              // version 29 (v24-31 header layout)
		int strOff = 96;
		String[] names = { "UnityEngine", "PlayerController", "GetPlayerHealth", "m_secretKey", "Awake" };
		int p = strOff;
		for (String n : names) {
			for (int i = 0; i < n.length(); i++) {
				buf[p++] = (byte) n.charAt(i);
			}
			buf[p++] = 0;
		}
		putLe(buf, 36, strOff);         // stringLiteralOffset
		putLe(buf, 40, p - strOff);     // stringLiteralSize
		return buf;
	}

	private static void putLe(byte[] b, int off, int v) {
		b[off] = (byte) v;
		b[off + 1] = (byte) (v >>> 8);
		b[off + 2] = (byte) (v >>> 16);
		b[off + 3] = (byte) (v >>> 24);
	}

	@Test
	void extractsCSharpNamesFromInjectedMetadata(@TempDir Path tmp) throws Exception {
		Path src = Path.of("../jadx-cli/src/test/resources/samples/resources-only.apk");
		assertTrue(Files.exists(src), "base APK fixture must exist");
		Path apk = tmp.resolve("unity.apk");
		Files.copy(src, apk);

		// Inject the synthetic global-metadata.dat as a zip entry via the zip filesystem.
		try (FileSystem zfs = FileSystems.newFileSystem(apk, (ClassLoader) null)) {
			Path dest = zfs.getPath("assets/bin/Data/Managed/Metadata/global-metadata.dat");
			Files.createDirectories(dest.getParent());
			Files.write(dest, synthMetadata());
		}

		String out = run("il2cpp-metadata-scan", apk.toString());
		assertTrue(out.contains("\"success\": true"), "should succeed: " + out);
		assertTrue(out.contains("\"found\": true"), "must locate & read the metadata: " + out);
		assertFalse(out.contains("Invalid IL2CPP magic"), "magic must survive raw read: " + out);
		assertTrue(out.contains("PlayerController"), "must recover C# class name: " + out);
	}

	private static String run(String... args) {
		PrintStream origOut = System.out;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			System.setOut(new PrintStream(baos));
			new CommandLine(new JadxAICLI()).execute(args);
		} finally {
			System.setOut(origOut);
		}
		String s = baos.toString();
		int i = s.indexOf('{');
		return i >= 0 ? s.substring(i) : s;
	}
}
