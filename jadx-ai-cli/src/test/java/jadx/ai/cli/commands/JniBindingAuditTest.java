package jadx.ai.cli.commands;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import picocli.CommandLine;

import jadx.ai.cli.JadxAICLI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards {@code jni-binding-audit}: the JNI short-name mangling (the subtle part — bugs here would
 * silently misclassify every method as dynamically registered) and the end-to-end structure on the
 * real {@code libcode.so} fixture.
 */
class JniBindingAuditTest {

	@Test
	void manglesSimpleName() {
		assertEquals("Java_com_example_Foo_bar",
				JniBindingAuditCommand.mangledPrefix("com.example.Foo", "bar"));
	}

	@Test
	void manglesUnderscoreInMethod() {
		// '_' → '_1' per the JNI spec so the '_' package separator stays unambiguous.
		assertEquals("Java_com_ex_A_get_1value",
				JniBindingAuditCommand.mangledPrefix("com.ex.A", "get_value"));
	}

	@Test
	void manglesUnderscoreInPackage() {
		assertEquals("Java_com_foo_1bar_A_x",
				JniBindingAuditCommand.mangledPrefix("com.foo_bar.A", "x"));
	}

	@Test
	void manglesNonAsciiAsHex() {
		// A non-ASCII-alnum char (here '$', the inner-class marker, 0x24) → _0XXXX.
		assertEquals("Java_com_A_00024B_m",
				JniBindingAuditCommand.mangledPrefix("com.A$B", "m"));
	}

	@Test
	void runsAgainstRealLibFixture() {
		Path apk = Path.of("../jadx-cli/src/test/resources/samples/resources-only.apk");
		String out = run("jni-binding-audit", apk.toString());
		assertTrue(out.contains("\"success\": true"), "should succeed: " + out);
		assertTrue(out.contains("\"analyzedLibraries\""), "must list analyzed libs: " + out);
		assertTrue(out.contains("libcode.so"), "must analyze the bundled .so: " + out);
		assertTrue(out.contains("\"dynamicallyRegistered\""), "must report binding split: " + out);
		assertTrue(out.contains("\"orphanExports\""), "must report orphan exports: " + out);
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
