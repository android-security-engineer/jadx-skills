package jadx.ai.cli.commands;

import java.io.File;
import java.util.Map;
import java.util.Set;

import jadx.api.JadxDecompiler;

/**
 * Single source of truth for executing a CLI command by name against a loaded
 * {@link JadxDecompiler}. Lives in the {@code commands} package so it can populate each command's
 * (package-private/protected) option fields directly.
 *
 * <p>All transports — the daemon ({@code jadx.ai.cli.daemon}), the MCP bridge
 * ({@code jadx.ai.cli.mcp}) and the unified server — delegate here instead of duplicating the
 * field-mapping switch. Adding a command now means: write the command class, register it in
 * {@link jadx.ai.cli.JadxAICLI}, add a case here, and (for MCP) a tool definition. The previous
 * four-site duplication (and the cross-package {@code protected}-access breakage it caused) is
 * gone.
 */
public final class CommandDispatch {

	private CommandDispatch() {
	}

	/**
	 * Commands that must not be served from / stored in the read-through cache. Either they mutate
	 * decompiler state ({@code rename}/{@code reload}/...) or they invoke an external tool with
	 * side effects on the filesystem ({@code apktool}), where a cached result would be wrong.
	 */
	private static final Set<String> MUTATION_COMMANDS = Set.of(
			"rename", "reload", "export", "script", "comment", "apktool", "adb", "frida");

	/** Every command name this dispatcher understands. */
	private static final Set<String> KNOWN_COMMANDS = Set.of(
			"search", "usage", "list", "info", "class-detail", "decompile",
			"rename", "reload", "export", "resources", "line-map", "package-detail",
			"graph", "hook", "navigate", "comment", "cfg", "signature", "script",
			"secrets-scan", "ioc-extract", "permission-risk-map", "native-bridge-index",
			"crypto-scan", "manifest-audit", "deep-link-audit", "network-security-config",
			"obfuscation-report", "native-libs", "ssl-scan", "webview-scan", "framework-detect",
			"storage-scan", "intent-scan", "sql-injection-scan", "command-injection-scan",
			"logging-scan", "path-traversal-scan", "serialization-scan", "clipboard-scan",
			"tamper-detection-scan", "tapjacking-scan", "dynamic-loading-scan", "biometric-scan",
			"accessibility-scan", "keystore-scan", "exported-provider-scan",
			"notification-listener-scan", "sms-scan", "privacy-scan", "task-hijacking-scan",
			"firebase-scan", "xxe-scan", "intent-redirection-scan", "cert-pinning-scan", "debug-artifact-scan", "deeplink-scan", "backup-scan", "screen-capture-scan", "otp-interception-scan", "pending-intent-scan", "content-provider-scan", "local-auth-bypass-scan", "unsafe-export-scan", "insecure-keystore-scan", "token-storage-scan", "webview-url-scan", "insecure-api-scan", "network-traffic-scan", "ad-fraud-scan", "runtime-integrity-scan", "hardcoded-crypto-scan", "permission-request-scan", "data-residue-scan", "subprocess-scan", "cryptographic-misuse-scan", "log-info-leak-scan", "broadcast-scan", "fragment-injection-scan", "unsafe-encryption-scan", "screenshot-leak-scan", "trust-boundary-scan", "insecure-deeplink-handler-scan", "insecure-file-io-scan",
			"sdk-inventory", "bypass-hook", "packer-detect", "capability-report", "native-lib-security", "api-endpoint-extract", "google-services-config", "dangerous-api-map", "manifest-security-audit", "il2cpp-metadata-scan", "flutter-analysis", "source-quality-report", "class-inventory", "entrypoint-scan", "dex-stat", "custom-permission-audit", "apk-signature", "dead-code-report", "method-complexity", "resource-inventory", "shared-uid-audit", "device-admin-scan", "vpn-service-scan", "nfc-scan", "sensor-scan", "alarm-wakelock-scan",
			"bluetooth-scan", "account-scan", "location-scan", "sim-info-scan",
			"smali", "find-classes", "string-xref", "call-sites",
		"apktool", "adb", "frida");

	public static boolean isKnown(String command) {
		return KNOWN_COMMANDS.contains(command);
	}

	public static Set<String> knownCommands() {
		return KNOWN_COMMANDS;
	}

	public static boolean isReadOnly(String command) {
		return !MUTATION_COMMANDS.contains(command);
	}

	/**
	 * Construct, configure and run the named command. Throws {@link IllegalArgumentException} for
	 * an unknown command.
	 */
	public static Object run(String command, Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		switch (command) {
			case "search":
				return search(args, decompiler);
			case "usage":
				return usage(args, decompiler);
			case "list":
				return list(args, decompiler);
			case "info":
				return new InfoCommand().execute(decompiler);
			case "class-detail":
				return classDetail(args, decompiler);
			case "decompile":
				return decompile(args, decompiler);
			case "rename":
				return rename(args, decompiler);
			case "reload":
				return reload(args, decompiler);
			case "export":
				return export(args, decompiler);
			case "resources":
				return resources(args, decompiler);
			case "line-map":
				return lineMap(args, decompiler);
			case "package-detail":
				return packageDetail(args, decompiler);
			case "graph":
				return graph(args, decompiler);
			case "hook":
				return hook(args, decompiler);
			case "navigate":
				return navigate(args, decompiler);
			case "comment":
				return comment(args, decompiler);
			case "cfg":
				return cfg(args, decompiler);
			case "signature":
				return new SignatureCommand().execute(decompiler);
			case "script":
				return script(args, decompiler);
			case "secrets-scan":
				return applyAndRun(new SecretsScanCommand(), args, decompiler);
			case "ioc-extract":
				return applyAndRun(new IocExtractCommand(), args, decompiler);
			case "permission-risk-map":
				return applyAndRun(new PermissionRiskMapCommand(), args, decompiler);
			case "native-bridge-index":
				return applyAndRun(new NativeBridgeIndexCommand(), args, decompiler);
			case "crypto-scan":
				return applyAndRun(new CryptoScanCommand(), args, decompiler);
			case "manifest-audit":
				return applyAndRun(new ManifestAuditCommand(), args, decompiler);
			case "deep-link-audit":
				return applyAndRun(new DeepLinkAuditCommand(), args, decompiler);
			case "network-security-config":
				return applyAndRun(new NetworkSecurityConfigCommand(), args, decompiler);
			case "obfuscation-report":
				return applyAndRun(new ObfuscationReportCommand(), args, decompiler);
			case "native-libs":
				return applyAndRun(new NativeLibsCommand(), args, decompiler);
			case "ssl-scan":
				return applyAndRun(new SslScanCommand(), args, decompiler);
			case "webview-scan":
				return applyAndRun(new WebviewScanCommand(), args, decompiler);
			case "framework-detect":
				return applyAndRun(new FrameworkDetectCommand(), args, decompiler);
			case "storage-scan":
				return applyAndRun(new StorageScanCommand(), args, decompiler);
			case "intent-scan":
				return applyAndRun(new IntentScanCommand(), args, decompiler);
			case "sql-injection-scan":
				return applyAndRun(new SqlInjectionScanCommand(), args, decompiler);
			case "command-injection-scan":
				return applyAndRun(new CommandInjectionScanCommand(), args, decompiler);
			case "logging-scan":
				return applyAndRun(new LoggingScanCommand(), args, decompiler);
			case "path-traversal-scan":
				return applyAndRun(new PathTraversalScanCommand(), args, decompiler);
			case "serialization-scan":
				return applyAndRun(new SerializationScanCommand(), args, decompiler);
			case "clipboard-scan":
				return applyAndRun(new ClipboardScanCommand(), args, decompiler);
			case "tamper-detection-scan":
				return applyAndRun(new TamperDetectionScanCommand(), args, decompiler);
			case "tapjacking-scan":
				return applyAndRun(new TapjackingScanCommand(), args, decompiler);
			case "dynamic-loading-scan":
				return applyAndRun(new DynamicLoadingScanCommand(), args, decompiler);
			case "biometric-scan":
				return applyAndRun(new BiometricScanCommand(), args, decompiler);
			case "accessibility-scan":
				return applyAndRun(new AccessibilityScanCommand(), args, decompiler);
			case "keystore-scan":
				return applyAndRun(new KeystoreScanCommand(), args, decompiler);
			case "exported-provider-scan":
				return applyAndRun(new ExportedProviderScanCommand(), args, decompiler);
			case "notification-listener-scan":
				return applyAndRun(new NotificationListenerScanCommand(), args, decompiler);
			case "sms-scan":
				return applyAndRun(new SmsScanCommand(), args, decompiler);
			case "privacy-scan":
				return applyAndRun(new PrivacyScanCommand(), args, decompiler);
			case "task-hijacking-scan":
				return applyAndRun(new TaskHijackingScanCommand(), args, decompiler);
			case "firebase-scan":
				return applyAndRun(new FirebaseScanCommand(), args, decompiler);
			case "xxe-scan":
				return applyAndRun(new XxeScanCommand(), args, decompiler);
			case "intent-redirection-scan":
				return applyAndRun(new IntentRedirectionScanCommand(), args, decompiler);
			case "cert-pinning-scan":
				return applyAndRun(new CertPinningScanCommand(), args, decompiler);
			case "debug-artifact-scan":
				return applyAndRun(new DebugArtifactScanCommand(), args, decompiler);
			case "deeplink-scan":
				return applyAndRun(new DeeplinkScanCommand(), args, decompiler);
			case "backup-scan":
				return applyAndRun(new BackupScanCommand(), args, decompiler);
			case "screen-capture-scan":
				return applyAndRun(new ScreenCaptureScanCommand(), args, decompiler);
			case "otp-interception-scan":
				return applyAndRun(new OtpInterceptionScanCommand(), args, decompiler);
			case "pending-intent-scan":
				return applyAndRun(new PendingIntentScanCommand(), args, decompiler);
			case "content-provider-scan":
				return applyAndRun(new ContentProviderScanCommand(), args, decompiler);
			case "local-auth-bypass-scan":
				return applyAndRun(new LocalAuthBypassScanCommand(), args, decompiler);
			case "unsafe-export-scan":
				return applyAndRun(new UnsafeExportScanCommand(), args, decompiler);
			case "insecure-keystore-scan":
				return applyAndRun(new InsecureKeystoreScanCommand(), args, decompiler);
			case "token-storage-scan":
				return applyAndRun(new TokenStorageScanCommand(), args, decompiler);
			case "webview-url-scan":
				return applyAndRun(new WebViewUrlScanCommand(), args, decompiler);
			case "insecure-api-scan":
				return applyAndRun(new InsecureApiScanCommand(), args, decompiler);
			case "network-traffic-scan":
				return applyAndRun(new NetworkTrafficScanCommand(), args, decompiler);
			case "ad-fraud-scan":
				return applyAndRun(new AdFraudScanCommand(), args, decompiler);
			case "runtime-integrity-scan":
				return applyAndRun(new RuntimeIntegrityScanCommand(), args, decompiler);
			case "hardcoded-crypto-scan":
				return applyAndRun(new HardcodedCryptoScanCommand(), args, decompiler);
			case "permission-request-scan":
				return applyAndRun(new PermissionRequestScanCommand(), args, decompiler);
			case "data-residue-scan":
				return applyAndRun(new DataResidueScanCommand(), args, decompiler);
			case "subprocess-scan":
				return applyAndRun(new SubprocessScanCommand(), args, decompiler);
			case "cryptographic-misuse-scan":
				return applyAndRun(new CryptographicMisuseScanCommand(), args, decompiler);
			case "log-info-leak-scan":
				return applyAndRun(new LogInfoLeakScanCommand(), args, decompiler);
			case "broadcast-scan":
				return applyAndRun(new BroadcastScanCommand(), args, decompiler);
			case "fragment-injection-scan":
				return applyAndRun(new FragmentInjectionScanCommand(), args, decompiler);
			case "unsafe-encryption-scan":
				return applyAndRun(new UnsafeEncryptionScanCommand(), args, decompiler);
			case "screenshot-leak-scan":
				return applyAndRun(new ScreenshotLeakScanCommand(), args, decompiler);
			case "trust-boundary-scan":
				return applyAndRun(new TrustBoundaryScanCommand(), args, decompiler);
			case "insecure-deeplink-handler-scan":
				return applyAndRun(new InsecureDeeplinkHandlerScanCommand(), args, decompiler);
			case "insecure-file-io-scan":
				return applyAndRun(new InsecureFileIoScanCommand(), args, decompiler);
			case "sdk-inventory":
				return applyAndRun(new SdkInventoryCommand(), args, decompiler);
			case "bypass-hook":
				return applyAndRun(new BypassHookCommand(), args, decompiler);
			case "packer-detect":
				return applyAndRun(new PackerDetectCommand(), args, decompiler);
			case "capability-report":
				return applyAndRun(new CapabilityReportCommand(), args, decompiler);
			case "native-lib-security":
				return applyAndRun(new NativeLibSecurityCommand(), args, decompiler);
			case "api-endpoint-extract":
				return applyAndRun(new ApiEndpointExtractCommand(), args, decompiler);
			case "google-services-config":
				return applyAndRun(new GoogleServicesConfigCommand(), args, decompiler);
			case "dangerous-api-map":
				return applyAndRun(new DangerousApiMapCommand(), args, decompiler);
			case "manifest-security-audit":
				return applyAndRun(new ManifestSecurityAuditCommand(), args, decompiler);
			case "il2cpp-metadata-scan":
				return applyAndRun(new Il2cppMetadataScanCommand(), args, decompiler);
			case "flutter-analysis":
				return applyAndRun(new FlutterAnalysisCommand(), args, decompiler);
			case "source-quality-report":
				return applyAndRun(new SourceQualityReportCommand(), args, decompiler);
			case "class-inventory":
				return applyAndRun(new ClassInventoryCommand(), args, decompiler);
			case "entrypoint-scan":
				return applyAndRun(new EntrypointScanCommand(), args, decompiler);
			case "dex-stat":
				return applyAndRun(new DexStatCommand(), args, decompiler);
			case "custom-permission-audit":
				return applyAndRun(new CustomPermissionAuditCommand(), args, decompiler);
			case "apk-signature":
				return applyAndRun(new ApkSignatureCommand(), args, decompiler);
			case "dead-code-report":
				return applyAndRun(new DeadCodeReportCommand(), args, decompiler);
			case "method-complexity":
				return applyAndRun(new MethodComplexityCommand(), args, decompiler);
			case "resource-inventory":
				return applyAndRun(new ResourceInventoryCommand(), args, decompiler);
			case "shared-uid-audit":
				return applyAndRun(new SharedUidAuditCommand(), args, decompiler);
			case "device-admin-scan":
				return applyAndRun(new DeviceAdminScanCommand(), args, decompiler);
			case "vpn-service-scan":
				return applyAndRun(new VpnServiceScanCommand(), args, decompiler);
			case "nfc-scan":
				return applyAndRun(new NfcScanCommand(), args, decompiler);
			case "sensor-scan":
				return applyAndRun(new SensorScanCommand(), args, decompiler);
			case "alarm-wakelock-scan":
				return applyAndRun(new AlarmWakelockScanCommand(), args, decompiler);
			case "bluetooth-scan":
				return applyAndRun(new BluetoothScanCommand(), args, decompiler);
			case "account-scan":
				return applyAndRun(new AccountScanCommand(), args, decompiler);
			case "location-scan":
				return applyAndRun(new LocationScanCommand(), args, decompiler);
			case "sim-info-scan":
				return applyAndRun(new SimInfoScanCommand(), args, decompiler);
			case "smali":
				return applyAndRun(new SmaliCommand(), args, decompiler);
			case "find-classes":
				return applyAndRun(new FindClassesCommand(), args, decompiler);
			case "string-xref":
				return applyAndRun(new StringXrefCommand(), args, decompiler);
			case "call-sites":
				return applyAndRun(new CallSitesCommand(), args, decompiler);
		case "apktool":
				return applyAndRun(new ApktoolCommand(), args, decompiler);
			case "adb":
				return applyAndRun(new AdbCommand(), args, decompiler);
			case "frida":
				return applyAndRun(new FridaCommand(), args, decompiler);
			default:
				throw new IllegalArgumentException("Unknown command: " + command);
		}
	}

	/** Newer commands self-map via {@link AbstractCommand#applyArgs}. */
	private static Object applyAndRun(AbstractCommand cmd, Map<String, Object> args, JadxDecompiler decompiler)
			throws Exception {
		cmd.applyArgs(args);
		return cmd.execute(decompiler);
	}

	private static Object search(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		SearchCommand cmd = new SearchCommand();
		cmd.searchType = (String) args.getOrDefault("type", "class");
		cmd.query = (String) args.getOrDefault("query", "");
		cmd.limit = intArg(args, "limit", 50);
		cmd.exact = bool(args, "exact");
		cmd.searchParent = bool(args, "searchParent");
		cmd.regex = bool(args, "regex");
		cmd.ignoreCase = bool(args, "ignoreCase");
		cmd.packageFilter = (String) args.get("package");
		cmd.resourceTypeFilter = (String) args.get("resourceType");
		cmd.maxResourceSizeKB = intArg(args, "maxSize", 512);
		return cmd.execute(decompiler);
	}

	private static Object usage(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		UsageCommand cmd = new UsageCommand();
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.fieldName = (String) args.get("field");
		cmd.queryType = (String) args.getOrDefault("type", "useIn");
		cmd.depth = intArg(args, "depth", 1);
		return cmd.execute(decompiler);
	}

	private static Object list(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		ListCommand cmd = new ListCommand();
		cmd.listType = (String) args.getOrDefault("type", "classes");
		cmd.packageName = (String) args.get("package");
		cmd.className = (String) args.get("class");
		cmd.verbose = bool(args, "verbose");
		cmd.withInners = bool(args, "withInners");
		return cmd.execute(decompiler);
	}

	private static Object classDetail(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		ClassDetailCommand cmd = new ClassDetailCommand();
		cmd.className = (String) args.get("class");
		return cmd.execute(decompiler);
	}

	private static Object decompile(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		DecompileCommand cmd = new DecompileCommand();
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.withSmali = bool(args, "withSmali");
		cmd.includeLineMap = bool(args, "lineMap");
		return cmd.execute(decompiler);
	}

	private static Object rename(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		RenameCommand cmd = new RenameCommand();
		cmd.targetType = (String) args.getOrDefault("type", "class");
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.fieldName = (String) args.get("field");
		cmd.packageName = (String) args.get("package");
		cmd.newName = (String) args.get("name");
		cmd.removeAlias = bool(args, "removeAlias");
		return cmd.execute(decompiler);
	}

	private static Object reload(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		ReloadCommand cmd = new ReloadCommand();
		cmd.className = (String) args.get("class");
		cmd.actionType = (String) args.getOrDefault("type", "reload");
		cmd.allClasses = bool(args, "all");
		return cmd.execute(decompiler);
	}

	private static Object export(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		ExportCommand cmd = new ExportCommand();
		String outputPath = (String) args.get("output");
		if (outputPath != null) {
			cmd.outputDir = new File(outputPath);
		}
		cmd.packageFilter = (String) args.get("package");
		cmd.classFilter = (String) args.get("class");
		cmd.exportFormat = (String) args.getOrDefault("format", "java");
		cmd.saveAll = bool(args, "saveAll");
		cmd.saveSources = bool(args, "saveSources");
		cmd.saveResources = bool(args, "saveResources");
		return cmd.execute(decompiler);
	}

	private static Object resources(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		ResourcesCommand cmd = new ResourcesCommand();
		cmd.resourceType = (String) args.get("type");
		cmd.nameFilter = (String) args.get("name");
		cmd.includeContent = bool(args, "content");
		return cmd.execute(decompiler);
	}

	private static Object lineMap(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		LineMapCommand cmd = new LineMapCommand();
		cmd.className = (String) args.get("class");
		cmd.includeAnnotations = bool(args, "annotations");
		cmd.includeUsageMap = bool(args, "usageMap");
		cmd.usePlacesNode = (String) args.get("usePlaces");
		cmd.sourceLine = intArg(args, "sourceLine", -1);
		cmd.nodeAtPos = intArg(args, "nodeAt", -1);
		cmd.closestNodePos = intArg(args, "closestNode", -1);
		cmd.enclosingNodePos = intArg(args, "enclosingNode", -1);
		cmd.annotationAtPos = intArg(args, "annotationAt", -1);
		return cmd.execute(decompiler);
	}

	private static Object packageDetail(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		PackageDetailCommand cmd = new PackageDetailCommand();
		cmd.packageName = (String) args.get("package");
		return cmd.execute(decompiler);
	}

	private static Object graph(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		GraphCommand cmd = new GraphCommand();
		cmd.graphType = (String) args.getOrDefault("type", "call");
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.depth = intArg(args, "depth", 3);
		cmd.outputFormat = (String) args.getOrDefault("format", "json");
		return cmd.execute(decompiler);
	}

	private static Object hook(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		HookCommand cmd = new HookCommand();
		cmd.hookType = (String) args.getOrDefault("type", "frida");
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.fieldName = (String) args.get("field");
		cmd.xposedLang = (String) args.getOrDefault("lang", "java");
		return cmd.execute(decompiler);
	}

	private static Object navigate(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		NavigateCommand cmd = new NavigateCommand();
		cmd.navType = (String) args.getOrDefault("type", "entry-points");
		return cmd.execute(decompiler);
	}

	private static Object comment(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		CommentCommand cmd = new CommentCommand();
		cmd.className = (String) args.get("class");
		cmd.opType = (String) args.getOrDefault("type", "list");
		cmd.query = (String) args.get("query");
		cmd.commentText = (String) args.get("commentText");
		cmd.methodName = (String) args.get("method");
		cmd.fieldName = (String) args.get("field");
		cmd.style = (String) args.getOrDefault("style", "LINE");
		cmd.insnOffset = intArg(args, "insnOffset", -1);
		return cmd.execute(decompiler);
	}

	private static Object cfg(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		CfgCommand cmd = new CfgCommand();
		cmd.className = (String) args.get("class");
		cmd.methodName = (String) args.get("method");
		cmd.cfgType = (String) args.getOrDefault("cfgType", "basic");
		cmd.outputFormat = (String) args.getOrDefault("format", "dot");
		return cmd.execute(decompiler);
	}

	private static Object script(Map<String, Object> args, JadxDecompiler decompiler) throws Exception {
		ScriptCommand cmd = new ScriptCommand();
		String path = (String) args.get("script");
		if (path != null) {
			cmd.scriptFile = new File(path);
		}
		String engine = (String) args.get("engine");
		if (engine != null) {
			cmd.engineName = engine;
		}
		return cmd.execute(decompiler);
	}

	private static boolean bool(Map<String, Object> args, String key) {
		return Boolean.TRUE.equals(args.get(key));
	}

	private static int intArg(Map<String, Object> args, String key, int def) {
		return args.containsKey(key) && args.get(key) != null ? ((Number) args.get(key)).intValue() : def;
	}
}
