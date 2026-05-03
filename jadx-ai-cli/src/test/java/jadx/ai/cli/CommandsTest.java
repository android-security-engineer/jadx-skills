package jadx.ai.cli;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CommandsTest {

	private static File testDex;

	@BeforeAll
	static void setup() {
		testDex = new File("../jadx-cli/src/test/resources/samples/hello.dex");
		assertTrue(testDex.exists(), "Test DEX file must exist: " + testDex.getAbsolutePath());
	}

	@Test
	void testInfoCommand() {
		String output = runCommand("info", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"totalClasses\""), "Should contain totalClasses: " + output);
	}

	@Test
	void testListPackages() {
		String output = runCommand("list", "-t", "packages", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
	}

	@Test
	void testListClasses() {
		String output = runCommand("list", "-t", "classes", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"fullName\""), "Should contain fullName: " + output);
	}

	@Test
	void testSearchClass() {
		String output = runCommand("search", "-t", "class", "-q", "Hello", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
	}

	@Test
	void testSearchMethod() {
		String output = runCommand("search", "-t", "method", "-q", "main", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
	}

	@Test
	void testDecompileClass() {
		String output = runCommand("decompile", "-c", "Hello", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
	}

	@Test
	void testResourcesCommand() {
		String output = runCommand("resources", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
	}

	@Test
	void testUsageCommand() {
		String output = runCommand("usage", "-c", "Hello", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
	}

	@Test
	void testClassDetailCommand() {
		String output = runCommand("class-detail", "-c", "Hello", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"dependencies\""), "Should contain dependencies: " + output);
		assertTrue(output.contains("\"isNoCode\""), "Should contain isNoCode: " + output);
	}

	@Test
	void testPackageDetailCommand() {
		String output = runCommand("package-detail", "-p", "defpackage", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"isLeaf\""), "Should contain isLeaf: " + output);
	}

	@Test
	void testLineMapCommand() {
		String output = runCommand("line-map", "-c", "Hello", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"lineMap\""), "Should contain lineMap: " + output);
	}

	@Test
	void testUsageMethodWithOverrides() {
		String output = runCommand("usage", "-c", "Hello", "-m", "main", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"overrideRelatedMethods\""), "Should contain overrideRelatedMethods: " + output);
		assertTrue(output.contains("\"callsSelf\""), "Should contain callsSelf: " + output);
	}

	@Test
	void testListPackagesVerbose() {
		String output = runCommand("list", "-t", "packages", "-v", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"isLeaf\""), "Should contain isLeaf in verbose mode: " + output);
	}

	private String runCommand(String... args) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream captureStream = new PrintStream(baos);
		PrintStream oldOut = System.out;
		PrintStream oldErr = System.err;
		try {
			System.setOut(captureStream);
			System.setErr(new PrintStream(new ByteArrayOutputStream()));
			new picocli.CommandLine(new JadxAICLI()).execute(args);
		} finally {
			System.setOut(oldOut);
			System.setErr(oldErr);
		}
		return baos.toString();
	}
}
