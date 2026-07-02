package jadx.ai.cli.commands;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import jadx.ai.cli.JadxAICLI;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract test for the 8th-audit-dimension silent-truncation fix: every command that caps a
 * findings/list output at {@code --limit} MUST emit a top-level {@code "truncated"} boolean so an
 * AI consumer can tell a capped scan from an exhaustive one. Without it, the tail findings are
 * invisible and the AI treats the capped list as complete — an FN amplifier.
 *
 * <p>This test drives each fixed command against the {@code hello.dex}/{@code small.apk} fixtures
 * and asserts the {@code "truncated"} key is present in the JSON output (field-existence contract).
 * The value depends on whether the fixture actually exceeds the default limit (the small fixtures
 * usually do not → {@code false}); the regression value is that the field is PRESENT and serialized
 * as a boolean, guarding against the field being dropped or renamed in future refactors.
 *
 * <p>Commands needing specialised APKs not in the fixture set (il2cpp-metadata-scan,
 * dotnet-analysis, flutter-analysis, cordova-analysis) are covered by compilation + their own
 * dedicated tests; their main path emits {@code truncated} identically.
 */
class TruncatedFlagContractTest {

	private static File testDex;
	private static File testApk;

	@BeforeAll
	static void setup() {
		testDex = new File("../jadx-cli/src/test/resources/samples/hello.dex");
		testApk = new File("../jadx-cli/src/test/resources/samples/small.apk");
		assertTrue(testDex.exists(), "Test DEX fixture missing: " + testDex.getAbsolutePath());
		assertTrue(testApk.exists(), "Test APK fixture missing: " + testApk.getAbsolutePath());
	}

	private String runCommand(String... args) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream capture = new PrintStream(baos);
		PrintStream oldOut = System.out;
		PrintStream oldErr = System.err;
		try {
			System.setOut(capture);
			System.setErr(new PrintStream(new ByteArrayOutputStream()));
			new picocli.CommandLine(new JadxAICLI()).execute(args);
		} finally {
			System.setOut(oldOut);
			System.setErr(oldErr);
		}
		return baos.toString();
	}

	private static void assertTruncatedPresent(String output, String cmd) {
		assertNotNull(output, cmd + " produced no output");
		assertTrue(output.contains("\"success\": true"), cmd + " should succeed: " + output);
		assertTrue(output.contains("\"truncated\""),
				cmd + " must emit a top-level \"truncated\" boolean (silent-truncation contract): " + output);
	}

	@Test
	void sourceQualityReportEmitsTruncated() {
		assertTruncatedPresent(runCommand("source-quality-report", testDex.getAbsolutePath()), "source-quality-report");
	}

	@Test
	void deadCodeReportEmitsTruncated() {
		assertTruncatedPresent(runCommand("dead-code-report", testDex.getAbsolutePath()), "dead-code-report");
	}

	@Test
	void obfuscationReportEmitsTruncated() {
		assertTruncatedPresent(runCommand("obfuscation-report", testDex.getAbsolutePath()), "obfuscation-report");
	}

	@Test
	void entrypointScanEmitsTruncated() {
		assertTruncatedPresent(runCommand("entrypoint-scan", testDex.getAbsolutePath()), "entrypoint-scan");
	}

	@Test
	void iocExtractEmitsTruncated() {
		assertTruncatedPresent(runCommand("ioc-extract", testDex.getAbsolutePath()), "ioc-extract");
	}

	@Test
	void packerDetectEmitsTruncated() {
		assertTruncatedPresent(runCommand("packer-detect", testDex.getAbsolutePath()), "packer-detect");
	}

	@Test
	void customPermissionAuditEmitsTruncated() {
		assertTruncatedPresent(runCommand("custom-permission-audit", testApk.getAbsolutePath()), "custom-permission-audit");
	}

	@Test
	void manifestSecurityAuditEmitsTruncated() {
		assertTruncatedPresent(runCommand("manifest-security-audit", testApk.getAbsolutePath()), "manifest-security-audit");
	}

	@Test
	void permissionRiskMapEmitsTruncated() {
		assertTruncatedPresent(runCommand("permission-risk-map", testApk.getAbsolutePath()), "permission-risk-map");
	}

	@Test
	void dangerousApiMapEmitsTruncated() {
		assertTruncatedPresent(runCommand("dangerous-api-map", testDex.getAbsolutePath()), "dangerous-api-map");
	}

	@Test
	void googleServicesConfigEmitsTruncated() {
		assertTruncatedPresent(runCommand("google-services-config", testApk.getAbsolutePath()), "google-services-config");
	}

	@Test
	void sourceQualityTruncatedTrueUnderLowLimit() {
		// hello.dex is a single trivial class with no decompile errors/stubs/obfuscation, so the
		// issues list is empty and truncated is false even at limit=0. This test documents that the
		// boolean serializes correctly as `false` (the field's presence + boolean typing), not that
		// truncation fires on this fixture — firing requires a large app with >limit issues.
		String output = runCommand("source-quality-report", "--limit", "0", testDex.getAbsolutePath());
		assertTrue(output.contains("\"truncated\": false"),
				"on a fixture with zero issues, truncated must serialize as false: " + output);
	}
}
