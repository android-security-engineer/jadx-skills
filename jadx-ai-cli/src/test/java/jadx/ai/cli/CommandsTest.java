package jadx.ai.cli;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CommandsTest {

	private static File testDex;
	private static File testApk;

	@BeforeAll
	static void setup() {
		testDex = new File("../jadx-cli/src/test/resources/samples/hello.dex");
		assertTrue(testDex.exists(), "Test DEX file must exist: " + testDex.getAbsolutePath());
		testApk = new File("../jadx-cli/src/test/resources/samples/small.apk");
		assertTrue(testApk.exists(), "Test APK file must exist: " + testApk.getAbsolutePath());
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

	@Test
	void testClassDetailWithNewFields() {
		String output = runCommand("class-detail", "-c", "Hello", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"rawName\""), "Should contain rawName: " + output);
		assertTrue(output.contains("\"isClassInit\""), "Should contain isClassInit: " + output);
		assertTrue(output.contains("\"defPos\""), "Should contain defPos: " + output);
	}

	@Test
	void testUsageWithUnresolvedUsed() {
		String output = runCommand("usage", "-c", "Hello", "-m", "main", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"unresolvedUsed\""), "Should contain unresolvedUsed: " + output);
	}

	@Test
	void testSearchAlias() {
		String output = runCommand("search", "-t", "alias", "-q", "Hello", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
	}

	@Test
	void testLineMapWithUsageMap() {
		String output = runCommand("line-map", "-c", "Hello", "--usage-map", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"usageMap\""), "Should contain usageMap: " + output);
	}

	@Test
	void testListWithInners() {
		String output = runCommand("list", "-t", "classes", "--with-inners", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
	}

	@Test
	void testLineMapWithUsePlaces() {
		String output = runCommand("line-map", "-c", "Hello", "--use-places", "Hello.main", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"usePlaces\""), "Should contain usePlaces: " + output);
	}

	@Test
	void testLineMapWithSourceLine() {
		String output = runCommand("line-map", "-c", "Hello", "--source-line", "3", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"sourceLineResult\""), "Should contain sourceLineResult: " + output);
	}

	@Test
	void testInfoWithErrorsReport() {
		String output = runCommand("info", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"errorsReport\""), "Should contain errorsReport: " + output);
	}

	@Test
	void testSearchWithParent() {
		String output = runCommand("search", "-t", "class", "-q", "Hello", "--search-parent", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
	}

	@Test
	void testClassDetailDefPosAndRawName() {
		String output = runCommand("class-detail", "-c", "Hello", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"defPos\""), "Should contain defPos: " + output);
		assertTrue(output.contains("\"rawName\""), "Should contain rawName: " + output);
	}

	@Test
	void testLineMapNodeAtPosition() {
		String output = runCommand("line-map", "-c", "Hello", "--node-at", "0", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"nodeAtPosition\""), "Should contain nodeAtPosition: " + output);
	}

	@Test
	void testLineMapClosestNode() {
		String output = runCommand("line-map", "-c", "Hello", "--closest-node", "0", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"closestNode\""), "Should contain closestNode: " + output);
	}

	@Test
	void testLineMapEnclosingNode() {
		String output = runCommand("line-map", "-c", "Hello", "--enclosing-node", "0", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"enclosingNode\""), "Should contain enclosingNode: " + output);
	}

	@Test
	void testLineMapAnnotationAt() {
		String output = runCommand("line-map", "-c", "Hello", "--annotation-at", "0", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"annotationAt\""), "Should contain annotationAt: " + output);
	}

	@Test
	void testUsageClassUsed() {
		String output = runCommand("usage", "-c", "Hello", "-t", "used", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		assertTrue(output.contains("\"used\""), "Should contain used queryType: " + output);
	}

	// --- M1 native static-analysis commands (absorbed RE capabilities) ---

	@Test
	void testSecretsScanCommand() {
		String output = runCommand("secrets-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"count\""), "Should contain count: " + output);
	}

	@Test
	void testIocExtractCommand() {
		String output = runCommand("ioc-extract", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"urls\""), "Should contain urls: " + output);
		assertTrue(output.contains("\"endpoints\""), "Should contain endpoints: " + output);
	}

	@Test
	void testPermissionRiskMapCommand() {
		String output = runCommand("permission-risk-map", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"declaredPermissions\""), "Should contain declaredPermissions: " + output);
		assertTrue(output.contains("\"dangerous\""), "Should contain dangerous: " + output);
	}

	@Test
	void testNativeBridgeIndexCommand() {
		String output = runCommand("native-bridge-index", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"entries\""), "Should contain entries: " + output);
		assertTrue(output.contains("\"count\""), "Should contain count: " + output);
	}

	@Test
	void testCryptoScanCommand() {
		String output = runCommand("crypto-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"count\""), "Should contain count: " + output);
	}

	@Test
	void testManifestAuditCommand() {
		String output = runCommand("manifest-audit", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"exportedComponents\""), "Should contain exportedComponents: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
	}

	@Test
	void testDeepLinkAuditCommand() {
		String output = runCommand("deep-link-audit", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"deepLinks\""), "Should contain deepLinks: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
	}

	@Test
	void testNetworkSecurityConfigCommand() {
		String output = runCommand("network-security-config", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"referenced\""), "Should contain referenced: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
	}

	@Test
	void testObfuscationReportCommand() {
		String output = runCommand("obfuscation-report", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"nameObfuscation\""), "Should contain nameObfuscation: " + output);
		assertTrue(output.contains("\"stringDecryptCandidates\""), "Should contain stringDecryptCandidates: " + output);
	}

	@Test
	void testFrameworkDetectCommand() {
		String output = runCommand("framework-detect", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"primary\""), "Should contain primary: " + output);
		assertTrue(output.contains("\"isCrossPlatform\""), "Should contain isCrossPlatform: " + output);
	}

	@Test
	void testWebviewScanCommand() {
		String output = runCommand("webview-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"jsBridgeExposed\""), "Should contain jsBridgeExposed: " + output);
	}

	@Test
	void testSslScanCommand() {
		String output = runCommand("ssl-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"count\""), "Should contain count: " + output);
	}

	@Test
	void testLoggingScanCommand() {
		String output = runCommand("logging-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"logCallTotal\""), "Should contain logCallTotal: " + output);
	}

	@Test
	void testPathTraversalScanCommand() {
		String output = runCommand("path-traversal-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"zipSlipCount\""), "Should contain zipSlipCount: " + output);
	}

	@Test
	void testSerializationScanCommand() {
		String output = runCommand("serialization-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
	}

	@Test
	void testClipboardScanCommand() {
		String output = runCommand("clipboard-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"monitorsClipboard\""), "Should contain monitorsClipboard: " + output);
	}

	@Test
	void testTamperDetectionScanCommand() {
		String output = runCommand("tamper-detection-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"present\""), "Should contain present: " + output);
	}

	@Test
	void testTapjackingScanCommand() {
		String output = runCommand("tapjacking-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"usesOverlays\""), "Should contain usesOverlays: " + output);
	}

	@Test
	void testDynamicLoadingScanCommand() {
		String output = runCommand("dynamic-loading-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"usesDynamicLoading\""), "Should contain usesDynamicLoading: " + output);
	}

	@Test
	void testPrivacyScanCommand() {
		String output = runCommand("privacy-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"categories\""), "Should contain categories: " + output);
		assertTrue(output.contains("\"present\""), "Should contain present: " + output);
	}

	@Test
	void testIntentRedirectionScanCommand() {
		String output = runCommand("intent-redirection-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"redirectionClasses\""), "Should contain redirectionClasses: " + output);
	}

	@Test
	void testCertPinningScanCommand() {
		String output = runCommand("cert-pinning-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"pinsCertificates\""), "Should contain pinsCertificates: " + output);
		assertTrue(output.contains("\"mechanisms\""), "Should contain mechanisms: " + output);
		assertTrue(output.contains("\"pinnedHosts\""), "Should contain pinnedHosts: " + output);
	}

	@Test
	void testDebugArtifactScanCommand() {
		String output = runCommand("debug-artifact-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"hasDebugLibs\""), "Should contain hasDebugLibs: " + output);
		assertTrue(output.contains("\"hasDebugBranches\""), "Should contain hasDebugBranches: " + output);
		assertTrue(output.contains("\"debugLibs\""), "Should contain debugLibs: " + output);
	}

	@Test
	void testDeeplinkScanCommand() {
		String output = runCommand("deeplink-scan", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"hasDeepLinks\""), "Should contain hasDeepLinks: " + output);
		assertTrue(output.contains("\"schemes\""), "Should contain schemes: " + output);
		assertTrue(output.contains("\"hosts\""), "Should contain hosts: " + output);
	}

	@Test
	void testBackupScanCommand() {
		String output = runCommand("backup-scan", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"allowsBackup\""), "Should contain allowsBackup: " + output);
		assertTrue(output.contains("\"hasBackupAgent\""), "Should contain hasBackupAgent: " + output);
	}

	@Test
	void testScreenCaptureScanCommand() {
		String output = runCommand("screen-capture-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"hasFlagSecure\""), "Should contain hasFlagSecure: " + output);
		assertTrue(output.contains("\"hasMediaProjection\""), "Should contain hasMediaProjection: " + output);
	}

	@Test
	void testOtpInterceptionScanCommand() {
		String output = runCommand("otp-interception-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"otpChannels\""), "Should contain otpChannels: " + output);
	}

	@Test
	void testPendingIntentScanCommand() {
		String output = runCommand("pending-intent-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
	}

	@Test
	void testContentProviderScanCommand() {
		String output = runCommand("content-provider-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"unvalidatedProviders\""), "Should contain unvalidatedProviders: " + output);
	}

	@Test
	void testLocalAuthBypassScanCommand() {
		String output = runCommand("local-auth-bypass-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"bypassMethods\""), "Should contain bypassMethods: " + output);
	}

	@Test
	void testUnsafeExportScanCommand() {
		String output = runCommand("unsafe-export-scan", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"exportedWithoutPermission\""), "Should contain exportedWithoutPermission: " + output);
		assertTrue(output.contains("\"implicitlyExported\""), "Should contain implicitlyExported: " + output);
	}

	@Test
	void testInsecureKeystoreScanCommand() {
		String output = runCommand("insecure-keystore-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
	}

	@Test
	void testTokenStorageScanCommand() {
		String output = runCommand("token-storage-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"tokenStorageLocations\""), "Should contain tokenStorageLocations: " + output);
	}

	@Test
	void testWebViewUrlScanCommand() {
		String output = runCommand("webview-url-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasWhitelist\""), "Should contain hasWhitelist: " + output);
	}

	@Test
	void testInsecureApiScanCommand() {
		String output = runCommand("insecure-api-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
	}

	@Test
	void testNetworkTrafficScanCommand() {
		String output = runCommand("network-traffic-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasCleartextTraffic\""), "Should contain hasCleartextTraffic: " + output);
	}

	@Test
	void testAdFraudScanCommand() {
		String output = runCommand("ad-fraud-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasClickFraud\""), "Should contain hasClickFraud: " + output);
		assertTrue(output.contains("\"adSdks\""), "Should contain adSdks: " + output);
	}

	@Test
	void testRuntimeIntegrityScanCommand() {
		String output = runCommand("runtime-integrity-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasSignatureVerify\""), "Should contain hasSignatureVerify: " + output);
		assertTrue(output.contains("\"hasFridaDetect\""), "Should contain hasFridaDetect: " + output);
	}

	@Test
	void testHardcodedCryptoScanCommand() {
		String output = runCommand("hardcoded-crypto-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasHardcodedIv\""), "Should contain hasHardcodedIv: " + output);
		assertTrue(output.contains("\"hasHardcodedKey\""), "Should contain hasHardcodedKey: " + output);
	}

	@Test
	void testPermissionRequestScanCommand() {
		String output = runCommand("permission-request-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasPermissionCheck\""), "Should contain hasPermissionCheck: " + output);
		assertTrue(output.contains("\"hasRationale\""), "Should contain hasRationale: " + output);
	}

	@Test
	void testDataResidueScanCommand() {
		String output = runCommand("data-residue-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasExternalStorageWrite\""), "Should contain hasExternalStorageWrite: " + output);
		assertTrue(output.contains("\"hasAccountRegister\""), "Should contain hasAccountRegister: " + output);
	}

	@Test
	void testSubprocessScanCommand() {
		String output = runCommand("subprocess-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasSuCommand\""), "Should contain hasSuCommand: " + output);
		assertTrue(output.contains("\"hasUserInputExec\""), "Should contain hasUserInputExec: " + output);
	}

	@Test
	void testCryptographicMisuseScanCommand() {
		String output = runCommand("cryptographic-misuse-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasEcbMode\""), "Should contain hasEcbMode: " + output);
		assertTrue(output.contains("\"hasWeakHash\""), "Should contain hasWeakHash: " + output);
	}

	@Test
	void testLogInfoLeakScanCommand() {
		String output = runCommand("log-info-leak-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasCredentialLeak\""), "Should contain hasCredentialLeak: " + output);
		assertTrue(output.contains("\"hasPiiLeak\""), "Should contain hasPiiLeak: " + output);
	}

	@Test
	void testBroadcastScanCommand() {
		String output = runCommand("broadcast-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasStickyBroadcast\""), "Should contain hasStickyBroadcast: " + output);
		assertTrue(output.contains("\"hasLocalBroadcast\""), "Should contain hasLocalBroadcast: " + output);
	}

	@Test
	void testFragmentInjectionScanCommand() {
		String output = runCommand("fragment-injection-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasFragmentInjection\""), "Should contain hasFragmentInjection: " + output);
	}

	@Test
	void testUnsafeEncryptionScanCommand() {
		String output = runCommand("unsafe-encryption-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasCustomCrypto\""), "Should contain hasCustomCrypto: " + output);
		assertTrue(output.contains("\"hasWeakCipher\""), "Should contain hasWeakCipher: " + output);
	}

	@Test
	void testScreenshotLeakScanCommand() {
		String output = runCommand("screenshot-leak-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasFlagSecure\""), "Should contain hasFlagSecure: " + output);
		assertTrue(output.contains("\"hasMissingFlagSecure\""), "Should contain hasMissingFlagSecure: " + output);
	}

	@Test
	void testTrustBoundaryScanCommand() {
		String output = runCommand("trust-boundary-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasAuthDecisionFromIntent\""), "Should contain hasAuthDecisionFromIntent: " + output);
	}

	@Test
	void testInsecureDeeplinkHandlerScanCommand() {
		String output = runCommand("insecure-deeplink-handler-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasPathTraversal\""), "Should contain hasPathTraversal: " + output);
		assertTrue(output.contains("\"hasSqlInjection\""), "Should contain hasSqlInjection: " + output);
	}

	@Test
	void testInsecureFileIoScanCommand() {
		String output = runCommand("insecure-file-io-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hasWorldReadable\""), "Should contain hasWorldReadable: " + output);
		assertTrue(output.contains("\"hasUnencryptedSensitive\""), "Should contain hasUnencryptedSensitive: " + output);
	}

	@Test
	void testXxeScanCommand() {
		String output = runCommand("xxe-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
		assertTrue(output.contains("\"hardenedClasses\""), "Should contain hardenedClasses: " + output);
	}

	@Test
	void testFirebaseScanCommand() {
		String output = runCommand("firebase-scan", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"databaseUrls\""), "Should contain databaseUrls: " + output);
		assertTrue(output.contains("\"openDbCheckUrls\""), "Should contain openDbCheckUrls: " + output);
		assertTrue(output.contains("\"products\""), "Should contain products: " + output);
	}

	@Test
	void testTaskHijackingScanCommand() {
		String output = runCommand("task-hijacking-scan", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"appLevelMitigated\""), "Should contain appLevelMitigated: " + output);
		assertTrue(output.contains("\"launcherVulnerable\""), "Should contain launcherVulnerable: " + output);
	}

	@Test
	void testSmsScanCommand() {
		String output = runCommand("sms-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"interceptsSms\""), "Should contain interceptsSms: " + output);
		assertTrue(output.contains("\"sendsSms\""), "Should contain sendsSms: " + output);
	}

	@Test
	void testNotificationListenerScanCommand() {
		String output = runCommand("notification-listener-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"readsNotifications\""), "Should contain readsNotifications: " + output);
		assertTrue(output.contains("\"extractsText\""), "Should contain extractsText: " + output);
	}

	@Test
	void testExportedProviderScanCommand() {
		String output = runCommand("exported-provider-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"providerClasses\""), "Should contain providerClasses: " + output);
	}

	@Test
	void testKeystoreScanCommand() {
		String output = runCommand("keystore-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"usesAndroidKeyStore\""), "Should contain usesAndroidKeyStore: " + output);
		assertTrue(output.contains("\"requiresUserAuth\""), "Should contain requiresUserAuth: " + output);
	}

	@Test
	void testAccessibilityScanCommand() {
		String output = runCommand("accessibility-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"readsScreen\""), "Should contain readsScreen: " + output);
		assertTrue(output.contains("\"automatesUi\""), "Should contain automatesUi: " + output);
	}

	@Test
	void testBiometricScanCommand() {
		String output = runCommand("biometric-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"usesCryptoObject\""), "Should contain usesCryptoObject: " + output);
	}

	@Test
	void testCommandInjectionScanCommand() {
		String output = runCommand("command-injection-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
	}

	@Test
	void testSqlInjectionScanCommand() {
		String output = runCommand("sql-injection-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"highSeverityCount\""), "Should contain highSeverityCount: " + output);
	}

	@Test
	void testIntentScanCommand() {
		String output = runCommand("intent-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"mutablePendingIntents\""), "Should contain mutablePendingIntents: " + output);
	}

	@Test
	void testStorageScanCommand() {
		String output = runCommand("storage-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"usesEncryptedPrefs\""), "Should contain usesEncryptedPrefs: " + output);
	}

	@Test
	void testNativeLibsCommand() {
		String output = runCommand("native-libs", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"libraries\""), "Should contain libraries: " + output);
		assertTrue(output.contains("\"libraryCount\""), "Should contain libraryCount: " + output);
	}

	// --- M2 external-tool adapter (apktool) ---
	// These exercise the adapter's own validation, which is independent of whether the apktool
	// binary is installed, so they stay deterministic on any machine/CI.

	@Test
	void testApktoolInvalidAction() {
		String output = runCommand("apktool", "--action", "frobnicate", "--apk", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": false"), "Should fail: " + output);
		assertTrue(output.contains("InvalidAction"), "Should report InvalidAction: " + output);
	}

	@Test
	void testApktoolMissingInput() {
		String output = runCommand("apktool", "--action", "decode");
		assertNotNull(output);
		assertTrue(output.contains("\"success\": false"), "Should fail: " + output);
		assertTrue(output.contains("MissingInput"), "Should report MissingInput: " + output);
	}

	// --- adb external-tool adapter (validation is binary-independent, stays deterministic on CI) ---

	@Test
	void testAdbInvalidAction() {
		String output = runCommand("adb", "--action", "frobnicate");
		assertNotNull(output);
		assertTrue(output.contains("\"success\": false"), "Should fail: " + output);
		assertTrue(output.contains("InvalidAction"), "Should report InvalidAction: " + output);
	}

	@Test
	void testAdbInstallMissingInput() {
		String output = runCommand("adb", "--action", "install");
		assertNotNull(output);
		assertTrue(output.contains("\"success\": false"), "Should fail: " + output);
		assertTrue(output.contains("MissingInput"), "Should report MissingInput: " + output);
	}

	// --- frida external-tool adapter (validation is binary-independent, stays deterministic on CI) ---

	@Test
	void testFridaInvalidAction() {
		String output = runCommand("frida", "--action", "frobnicate");
		assertNotNull(output);
		assertTrue(output.contains("\"success\": false"), "Should fail: " + output);
		assertTrue(output.contains("InvalidAction"), "Should report InvalidAction: " + output);
	}

	@Test
	void testFridaRunScriptMissingScript() {
		String output = runCommand("frida", "--action", "run-script", "--package", "com.example.app");
		assertNotNull(output);
		assertTrue(output.contains("\"success\": false"), "Should fail: " + output);
		assertTrue(output.contains("MissingInput"), "Should report MissingInput: " + output);
	}

	@Test
	void testSdkInventoryCommand() {
		String output = runCommand("sdk-inventory", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"sdks\""), "Should contain sdks: " + output);
		assertTrue(output.contains("\"sdkCount\""), "Should contain sdkCount: " + output);
		assertTrue(output.contains("\"categories\""), "Should contain categories: " + output);
	}

	@Test
	void testBypassHookCommand() {
		String output = runCommand("bypass-hook", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"scripts\""), "Should contain scripts: " + output);
		assertTrue(output.contains("\"detectedProtections\""), "Should contain detectedProtections: " + output);
		assertTrue(output.contains("\"package\""), "Should contain package: " + output);
	}

	@Test
	void testPackerDetectCommand() {
		String output = runCommand("packer-detect", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"packers\""), "Should contain packers: " + output);
		assertTrue(output.contains("\"isPacked\""), "Should contain isPacked: " + output);
	}

	@Test
	void testCapabilityReportCommand() {
		String output = runCommand("capability-report", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"capabilities\""), "Should contain capabilities: " + output);
		assertTrue(output.contains("\"topPermissionGroups\""), "Should contain topPermissionGroups: " + output);
		assertTrue(output.contains("\"summary\""), "Should contain summary: " + output);
	}

	@Test
	void testNativeLibSecurityCommand() {
		String output = runCommand("native-lib-security", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"libraries\""), "Should contain libraries: " + output);
		assertTrue(output.contains("\"libraryCount\""), "Should contain libraryCount: " + output);
		assertTrue(output.contains("\"highRiskCount\""), "Should contain highRiskCount: " + output);
	}

	@Test
	void testFridaTraceMissingTarget() {
		String output = runCommand("frida", "--action", "trace");
		assertNotNull(output);
		assertTrue(output.contains("\"success\": false"), "Should fail: " + output);
		assertTrue(output.contains("MissingInput"), "Should report MissingInput: " + output);
	}


	@Test
	void testApiEndpointExtractCommand() {
		String output = runCommand("api-endpoint-extract", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"endpoints\""), "Should contain endpoints: " + output);
	}

	@Test
	void testGoogleServicesConfigCommand() {
		String output = runCommand("google-services-config", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
	}

	@Test
	void testDangerousApiMapCommand() {
		String output = runCommand("dangerous-api-map", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"exercisedPermissions\""), "Should contain exercisedPermissions: " + output);
	}

	@Test
	void testManifestSecurityAuditCommand() {
		String output = runCommand("manifest-security-audit", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\"") || output.contains("\"error\""), "Should produce JSON output: " + output);
	}

	@Test
	void testIl2cppMetadataScanCommand() {
		String output = runCommand("il2cpp-metadata-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"found\"") || output.contains("\"identifiers\""),
				"Should contain found/identifiers: " + output);
	}

	@Test
	void testFlutterAnalysisCommand() {
		String output = runCommand("flutter-analysis", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"isFlutter\""), "Should contain isFlutter: " + output);
	}

	@Test
	void testSourceQualityReportCommand() {
		String output = runCommand("source-quality-report", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"overallScore\""), "Should contain overallScore: " + output);
	}

	@Test
	void testClassInventoryCommand() {
		String output = runCommand("class-inventory", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"totalClasses\""), "Should contain totalClasses: " + output);
		assertTrue(output.contains("\"topPackages\""), "Should contain topPackages: " + output);
	}

	@Test
	void testEntrypointScanCommand() {
		String output = runCommand("entrypoint-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"entrypoints\""), "Should contain entrypoints: " + output);
		assertTrue(output.contains("\"entrypointCount\""), "Should contain entrypointCount: " + output);
	}

	@Test
	void testDexStatCommand() {
		String output = runCommand("dex-stat", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"totalClasses\""), "Should contain totalClasses: " + output);
		assertTrue(output.contains("\"methodDensity\""), "Should contain methodDensity: " + output);
		assertTrue(output.contains("\"topPackages\""), "Should contain topPackages: " + output);
	}

	@Test
	void testCustomPermissionAuditCommand() {
		String output = runCommand("custom-permission-audit", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"permissionCount\""), "Should contain permissionCount: " + output);
	}

	@Test
	void testApkSignatureCommand() {
		String output = runCommand("apk-signature", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"isSigned\""), "Should contain isSigned: " + output);
		assertTrue(output.contains("\"signatureSchemes\""), "Should contain signatureSchemes: " + output);
	}

	@Test
	void testDeadCodeReportCommand() {
		String output = runCommand("dead-code-report", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"orphanCandidates\""), "Should contain orphanCandidates: " + output);
	}

	@Test
	void testMethodComplexityCommand() {
		String output = runCommand("method-complexity", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"topMethods\""), "Should contain topMethods: " + output);
		assertTrue(output.contains("\"maxComplexity\""), "Should contain maxComplexity: " + output);
	}

	@Test
	void testResourceInventoryCommand() {
		String output = runCommand("resource-inventory", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"categories\""), "Should contain categories: " + output);
		assertTrue(output.contains("\"totalResources\""), "Should contain totalResources: " + output);
	}

	@Test
	void testSharedUidAuditCommand() {
		String output = runCommand("shared-uid-audit", testApk.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"hasSharedUserId\""), "Should contain hasSharedUserId: " + output);
	}

	@Test
	void testDeviceAdminScanCommand() {
		String output = runCommand("device-admin-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"hasDeviceAdmin\""), "Should contain hasDeviceAdmin: " + output);
	}

	@Test
	void testVpnServiceScanCommand() {
		String output = runCommand("vpn-service-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"hasVpnService\""), "Should contain hasVpnService: " + output);
	}

	@Test
	void testNfcScanCommand() {
		String output = runCommand("nfc-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"handlesNfc\""), "Should contain handlesNfc: " + output);
	}

	@Test
	void testSensorScanCommand() {
		String output = runCommand("sensor-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"usesSensors\""), "Should contain usesSensors: " + output);
	}

	@Test
	void testAlarmWakelockScanCommand() {
		String output = runCommand("alarm-wakelock-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"usesAlarmManager\""), "Should contain usesAlarmManager: " + output);
	}

	@Test
	void testBluetoothScanCommand() {
		String output = runCommand("bluetooth-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"usesBluetooth\""), "Should contain usesBluetooth: " + output);
	}

	@Test
	void testAccountScanCommand() {
		String output = runCommand("account-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"usesAccountManager\""), "Should contain usesAccountManager: " + output);
	}

	@Test
	void testLocationScanCommand() {
		String output = runCommand("location-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"tracksLocation\""), "Should contain tracksLocation: " + output);
	}

	@Test
	void testSimInfoScanCommand() {
		String output = runCommand("sim-info-scan", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"findings\""), "Should contain findings: " + output);
		assertTrue(output.contains("\"readsSimIdentifiers\""), "Should contain readsSimIdentifiers: " + output);
	}

	@Test
	void testSmaliCommand() {
		String output = runCommand("smali", "-c", "HelloWorld", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"fullSmali\""), "Should contain fullSmali: " + output);
	}

	@Test
	void testFindClassesCommand() {
		String output = runCommand("find-classes", "--by", "super", "-q", "Object", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"matches\""), "Should contain matches: " + output);
	}

	@Test
	void testStringXrefCommand() {
		String output = runCommand("string-xref", "-q", "Hello", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"references\""), "Should contain references: " + output);
	}

	@Test
	void testCallSitesCommand() {
		String output = runCommand("call-sites", "-m", "println", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed: " + output);
		assertTrue(output.contains("\"callSites\""), "Should contain callSites: " + output);
	}

	@Test
	void testIocExtractDecodeDefangOption() {
		String output = runCommand("ioc-extract", "--decode-defang", testDex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\": true"), "Should succeed with --decode-defang: " + output);
	}

	// --- disk cache + on-disk symbol index (resource-reduction features) ---

	@Test
	void testDiskCodeCacheMode(@TempDir Path tmp) throws Exception {
		File dex = tmp.resolve("hello.dex").toFile();
		Files.copy(testDex.toPath(), dex.toPath());
		String output = runCommand("decompile", "-c", "Hello", "--cache-mode", "DISK", dex.getAbsolutePath());
		assertNotNull(output);
		assertTrue(output.contains("\"success\""), "Should contain success field: " + output);
		// The disk code cache spills decompiled sources next to the input.
		Path cacheDir = tmp.resolve("hello.jadx.cache").resolve("code").resolve("sources");
		assertTrue(Files.isDirectory(cacheDir), "Disk code cache sources dir should exist: " + cacheDir);
	}

	@Test
	void testSymbolIndexBuildStatusSearchClear(@TempDir Path tmp) throws Exception {
		File dex = tmp.resolve("hello.dex").toFile();
		Files.copy(testDex.toPath(), dex.toPath());

		// build (with strings so the string fast-path is exercised too)
		String build = runCommand("index", dex.getAbsolutePath(), "build", "--with-strings");
		assertTrue(build.contains("\"status\": \"built\""), "Should report built: " + build);
		assertTrue(build.contains("\"classes\": 1"), "Should index 1 class: " + build);

		// index files landed on disk
		Path symbols = tmp.resolve("hello.jadx.cache").resolve("symbols");
		assertTrue(Files.exists(symbols.resolve("classes.tsv")), "classes.tsv should exist");
		assertTrue(Files.exists(symbols.resolve("meta.properties")), "meta.properties should exist");

		// status reports valid
		String status = runCommand("index", dex.getAbsolutePath(), "status");
		assertTrue(status.contains("\"valid\": true"), "Index should be valid: " + status);
		assertTrue(status.contains("\"hasStrings\": true"), "Index should have strings: " + status);

		// search via index returns the expected class without loading the decompiler
		String search = runCommand("search", "-t", "class", "-q", "Hello", "--use-index", dex.getAbsolutePath());
		assertTrue(search.contains("\"success\""), "Search should succeed: " + search);
		assertTrue(search.contains("HelloWorld"), "Index search should find HelloWorld: " + search);

		// method fast-path
		String method = runCommand("search", "-t", "method", "-q", "main", "--use-index", dex.getAbsolutePath());
		assertTrue(method.contains("\"success\""), "Method search should succeed: " + method);
		assertTrue(method.contains("\"methodName\""), "Method search should return a method: " + method);

		// clear removes the index dir
		String clear = runCommand("index", dex.getAbsolutePath(), "clear");
		assertTrue(clear.contains("\"status\": \"cleared\""), "Should report cleared: " + clear);
		assertFalse(Files.exists(symbols), "symbols dir should be gone after clear: " + symbols);
	}

	@Test
	void testListClassesViaIndexMatchesDecompiler(@TempDir Path tmp) throws Exception {
		File dex = tmp.resolve("hello.dex").toFile();
		Files.copy(testDex.toPath(), dex.toPath());
		runCommand("index", dex.getAbsolutePath(), "build");

		// decompiler path and index path must return the same class with full field parity.
		String plain = runCommand("list", "-t", "classes", dex.getAbsolutePath());
		String indexed = runCommand("list", "-t", "classes", "--use-index", dex.getAbsolutePath());
		assertTrue(indexed.contains("HelloWorld"), "Index list should find HelloWorld: " + indexed);
		assertTrue(indexed.contains("\"isInner\""), "Index list should carry isInner: " + indexed);
		assertTrue(indexed.contains("\"accessStr\""), "Index list should carry accessStr: " + indexed);
		assertTrue(plain.contains("HelloWorld") && indexed.contains("HelloWorld"),
				"Both paths should list HelloWorld");
	}

	@Test
	void testUseIndexAutoBuildsOnMissAndReuses(@TempDir Path tmp) throws Exception {
		File dex = tmp.resolve("hello.dex").toFile();
		Files.copy(testDex.toPath(), dex.toPath());
		Path symbols = tmp.resolve("hello.jadx.cache").resolve("symbols");

		// First open: no index yet, but --use-index still answers AND warms the index as a side-effect.
		assertFalse(Files.exists(symbols.resolve("meta.properties")), "No index should exist yet");
		String first = runCommand("list", "-t", "classes", "--use-index", dex.getAbsolutePath());
		assertTrue(first.contains("HelloWorld"), "First run should still list classes: " + first);
		assertTrue(Files.exists(symbols.resolve("meta.properties")),
				"First --use-index run should have built the index for reuse");

		// Second open: index is now valid, so status confirms cross-open reuse is available.
		String status = runCommand("index", dex.getAbsolutePath(), "status");
		assertTrue(status.contains("\"valid\": true"), "Index should be reusable on the next open: " + status);
		String second = runCommand("list", "-t", "classes", "--use-index", dex.getAbsolutePath());
		assertTrue(second.contains("HelloWorld"), "Second run should list from the reused index: " + second);
	}
}
