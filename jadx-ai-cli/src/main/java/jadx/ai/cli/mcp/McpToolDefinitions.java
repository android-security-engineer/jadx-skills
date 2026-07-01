package jadx.ai.cli.mcp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Defines all MCP tool specifications with JSON Schema input schemas.
 */
public class McpToolDefinitions {

	public static List<Map<String, Object>> getAll() {
		List<Map<String, Object>> tools = new ArrayList<>();
		tools.add(tool("jadx_search",
				"Search for classes, methods, fields, strings, or resources in the decompiled APK",
				arg("query", "string", "Search query string", ""),
				optArg("type", "string", "Search type: class, method, field, string, resource", "class"),
				optArg("limit", "integer", "Maximum number of results", 50),
				optArg("exact", "boolean", "Match exactly (no substring)", false),
				optArg("regex", "boolean", "Treat query as regex pattern", false),
				optArg("ignoreCase", "boolean", "Case-insensitive search", false),
				optArg("package", "string", "Filter results by package name", null),
				optArg("resourceType", "string", "Filter resources by type", null),
				optArg("maxSize", "integer", "Max resource size in KB", 512)));

		tools.add(tool("jadx_decompile",
				"Decompile a class or method to Java source code",
				arg("class", "string", "Full class name to decompile", null),
				optArg("method", "string", "Method name to decompile (optional, decompiles entire class if omitted)", null),
				optArg("withSmali", "boolean", "Include smali/disassembly output", false),
				optArg("lineMap", "boolean", "Include source-to-bytecode line mapping", false)));

		tools.add(tool("jadx_class_detail",
				"Get detailed information about a class including fields, methods, and hierarchy",
				arg("class", "string", "Full class name", null)));

		tools.add(tool("jadx_usage",
				"Find where a class, method, or field is used in the codebase",
				arg("class", "string", "Full class name", null),
				optArg("method", "string", "Method name to search usage for", null),
				optArg("field", "string", "Field name to search usage for", null),
				optArg("type", "string", "Usage type: useIn, usedBy", "useIn"),
				optArg("depth", "integer", "Traversal depth for usage chain", 1)));

		tools.add(tool("jadx_list",
				"List classes, packages, or methods in the APK",
				optArg("type", "string", "List type: class, package, method", "class"),
				optArg("package", "string", "Filter by package name", null),
				optArg("withInners", "boolean", "Include inner classes", false),
				optArg("limit", "integer", "Maximum number of results", 100)));

		tools.add(tool("jadx_info",
				"Get APK/DEX file information including package name, permissions, and class count"));

		tools.add(tool("jadx_rename",
				"Rename a class, method, field, or package in the decompiled output",
				arg("name", "string", "New name to apply", null),
				optArg("type", "string", "Rename target type: class, method, field, package", "class"),
				optArg("class", "string", "Class name (required for class/method/field rename)", null),
				optArg("method", "string", "Method name (for method rename)", null),
				optArg("field", "string", "Field name (for field rename)", null),
				optArg("package", "string", "Package name (for package rename)", null),
				optArg("removeAlias", "boolean", "Remove existing alias instead of setting new one", false)));

		tools.add(tool("jadx_graph",
				"Generate call graph, inheritance graph, or usage graph",
				optArg("type", "string", "Graph type: call, inheritance, usage", "call"),
				optArg("class", "string", "Target class name (required for call and usage graphs)", null),
				optArg("method", "string", "Target method name (optional, for call graph)", null),
				optArg("depth", "integer", "Max traversal depth", 3),
				optArg("format", "string", "Output format: json, mermaid, dot", "json")));

		tools.add(tool("jadx_cfg",
				"Generate the control flow graph of a single method (basic blocks, edges, dominators)",
				arg("class", "string", "Target class full name", null),
				arg("method", "string", "Target method name", null),
				optArg("cfgType", "string", "CFG type: basic, raw, region", "basic"),
				optArg("format", "string", "Serialization: dot, text", "dot")));

		tools.add(tool("jadx_signature",
				"Verify the APK signing scheme (v1/v2/v3/v3.1 via apksig) and list signer certificate details, digests, and any verification errors/warnings"));

		tools.add(tool("jadx_reload",
				"Reload/recompile/unload class code in the live decompiler (invalidates cached decompiled output — use after rename to refresh a class)",
				optArg("class", "string", "Class full name to reload/unload (omit with all=true)", null),
				optArg("type", "string", "Action: reload, recompile, unload", "reload"),
				optArg("all", "boolean", "Apply the action to all classes", false)));

		tools.add(tool("jadx_script",
				"Run a JADX script against the loaded decompiler instance for custom scripted analysis/transformations",
				arg("script", "string", "Path to the script file to execute", null),
				optArg("engine", "string", "Script engine: js", "js")));

		tools.add(tool("jadx_hook",
				"Generate Frida or Xposed hook snippets for reverse engineering",
				arg("class", "string", "Target class name (full name)", null),
				optArg("type", "string", "Hook type: frida, xposed", "frida"),
				optArg("method", "string", "Target method name (optional, hooks all methods if not specified)", null),
				optArg("field", "string", "Target field name (optional)", null),
				optArg("lang", "string", "Xposed language: java, kotlin (only for xposed type)", "java")));

		tools.add(tool("jadx_navigate",
				"Navigate to APK entry points and key components (main activity, application class, manifest, etc.)",
				optArg("type", "string", "Navigation type: main-activity, application, manifest, entry-points", "entry-points")));

		tools.add(tool("jadx_comment",
				"Read code annotations and metadata comments from decompiled classes",
				arg("class", "string", "Target class name (full name)", null),
				optArg("type", "string", "Operation: list (all annotations), search (by keyword)", "list"),
				optArg("query", "string", "Search keyword for annotations (required for search type)", null)));

		tools.add(tool("jadx_resources",
				"List and read resources from the APK (manifest, layouts, strings, etc.)",
				optArg("type", "string", "Resource type filter (e.g., xml, png, json)", null),
				optArg("name", "string", "Resource name filter", null),
				optArg("content", "boolean", "Include resource content in output", false)));

		tools.add(tool("jadx_line_map",
				"Map between source line numbers and bytecode positions for a decompiled class",
				arg("class", "string", "Full class name", null),
				optArg("annotations", "boolean", "Include annotation positions", false),
				optArg("usageMap", "boolean", "Include usage mapping", false),
				optArg("usePlaces", "string", "Node name for use-places lookup", null),
				optArg("sourceLine", "integer", "Source line number to look up", -1),
				optArg("nodeAt", "integer", "Position to find node at", -1),
				optArg("closestNode", "integer", "Position to find closest node", -1),
				optArg("enclosingNode", "integer", "Position to find enclosing node", -1),
				optArg("annotationAt", "integer", "Position to find annotation at", -1)));

		tools.add(tool("jadx_export",
				"Export decompiled sources or resources to disk",
				optArg("output", "string", "Output directory path", null),
				optArg("package", "string", "Filter by package name", null),
				optArg("class", "string", "Filter by class name", null),
				optArg("format", "string", "Export format: java, gradle", "java"),
				optArg("saveAll", "boolean", "Save all (sources + resources)", false),
				optArg("saveSources", "boolean", "Save decompiled sources", false),
				optArg("saveResources", "boolean", "Save resources", false)));

		tools.add(tool("jadx_package_detail",
				"Get detailed information about a package including its classes",
				arg("package", "string", "Package name", null)));

		tools.add(tool("jadx_secrets_scan",
				"Scan decompiled code and resources for hardcoded secrets (API keys, tokens, private keys, credentials)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("minEntropy", "number", "Min Shannon entropy for generic secret detection", 3.5),
				optArg("includeResources", "boolean", "Also scan text resources (requires resources loaded)", false),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_ioc_extract",
				"Extract indicators of compromise: URLs, IP addresses, domains and REST endpoints from code",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("types", "string", "Comma-separated IOC types: url,ip,domain,endpoint", "url,ip,domain,endpoint"),
				optArg("defang", "boolean", "Defang indicators (http->hxxp, . -> [.])", false),
				optArg("limit", "integer", "Maximum indicators per category", 500)));

		tools.add(tool("jadx_permission_risk_map",
				"Map declared Android permissions to dangerous APIs and locate their call sites in code",
				optArg("dangerousOnly", "boolean", "Only report dangerous-class permissions", true),
				optArg("withCallsites", "boolean", "Locate API call sites in code", true),
				optArg("limit", "integer", "Maximum call sites per API", 50)));

		tools.add(tool("jadx_native_bridge_index",
				"Index JNI native methods and WebView JavaScript bridges (the native/JS attack surface)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("kind", "string", "What to index: jni, jsbridge, all", "all"),
				optArg("limit", "integer", "Maximum entries", 500)));

		tools.add(tool("jadx_crypto_scan",
				"Scan code for cryptographic API misuse: weak ciphers (DES/3DES/RC4), ECB mode, weak hashes (MD5/SHA-1), hardcoded keys, static IVs, insecure RNG",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_manifest_audit",
				"Audit AndroidManifest.xml: exported components without permission guard, debuggable, allowBackup, cleartext traffic",
				optArg("exportedOnly", "boolean", "Only report exported components, skip app-flag checks", false)));

		tools.add(tool("jadx_deep_link_audit",
				"Enumerate deep-link / URI intent-filters (the externally-reachable attack surface) and flag risky shapes (browsable http(s) without autoVerify, custom scheme with open host)"));

		tools.add(tool("jadx_obfuscation_report",
				"Measure obfuscation for deobfuscation triage: machine-generated name ratio, reflection density, string-decryption candidate methods, known packer/obfuscator signatures",
				optArg("package", "string", "Only analyse classes under this package prefix", null),
				optArg("limit", "integer", "Max samples/candidates per category", 50)));

		tools.add(tool("jadx_framework_detect",
				"Detect the app framework (Flutter, React Native, Unity IL2CPP/Mono, Xamarin/.NET, Cordova, Capacitor, NativeScript, Qt) from bundled .so / asset / class signatures — the triage step that decides whether the real logic is in Java or in a native blob (libapp.so / libil2cpp.so) needing blutter/Il2CppDumper"));

		tools.add(tool("jadx_webview_scan",
				"Scan code for dangerous WebView configuration: setAllowUniversalAccessFromFileURLs/setAllowFileAccessFromFileURLs (UXSS, local-file theft), addJavascriptInterface + setJavaScriptEnabled (JS->Java RCE), MIXED_CONTENT_ALWAYS_ALLOW, setWebContentsDebuggingEnabled, cleartext loadUrl",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_ssl_scan",
				"Scan code for insecure TLS/SSL trust enabling MITM: all-trusting X509TrustManager (empty checkServerTrusted, null getAcceptedIssuers), permissive hostname verification (verify()->true, ALLOW_ALL_HOSTNAME_VERIFIER), and WebView onReceivedSslError that proceeds past invalid certs",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_native_libs",
				"Triage bundled native .so libraries (the half jadx can't decompile): strings extraction, exported JNI_OnLoad/Java_* symbols, and categorised markers (URLs/IPs, dynamic loading, process exec, anti-debug/anti-frida, root detection, crypto, packer)",
				optArg("lib", "string", "Only analyse libraries whose path contains this substring", null),
				optArg("minLength", "integer", "Minimum printable-string length", 5),
				optArg("maxBytes", "integer", "Max bytes to read per .so", 67108864),
				optArg("limit", "integer", "Max findings/symbols per library", 100),
				optArg("allStrings", "boolean", "Also return extracted strings (capped by limit)", false)));

		tools.add(tool("jadx_logging_scan",
				"Scan code for sensitive data in logs (MASVS MSTG-STORAGE-3): Log.*/System.out/printStackTrace/Timber/Logger calls that mention passwords, tokens, secrets, session ids, or log device identifiers (IMEI/Android ID/MAC). Also reports total log-call count for release-build triage",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_privacy_scan",
				"Inventory personal-data collection (MASVS-PRIVACY): device identifiers (IMEI/IMSI/ANDROID_ID/serial), advertising ID, location, contacts, accounts, installed-apps enumeration, camera/microphone, calendar/call-log, motion sensors. Starts from code (not declared permissions) so it catches non-permissioned fingerprinting that permission-risk-map misses. Returns a categorized inventory",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 400)));

		tools.add(tool("jadx_task_hijacking_scan",
				"Detect StrandHogg task-hijacking susceptibility (MASVS MSTG-PLATFORM): launcher/exported activities that keep the default taskAffinity (no android:taskAffinity=\"\") and are not launchMode=\"singleInstance\", launchMode=\"singleTask\" StrandHogg preconditions, and allowTaskReparenting=\"true\". Recognizes the application-level taskAffinity=\"\" mitigation. Parses AndroidManifest.xml; not covered by manifest-audit or intent-scan",
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_firebase_scan",
				"Firebase/Google backend recon (apkleaks/MobSF style): Realtime Database URLs plus ready-to-test openDbCheckUrls (<db>/.json, the world-readable-DB misconfiguration check), Cloud Storage buckets (*.appspot.com / gs://), Google API keys (AIza...), mobilesdk app id (1:NN:android:HH), and which Firebase products the code uses. Scans code + strings.xml/ARSC; backend-service-aware unlike secrets-scan/ioc-extract",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("noResources", "boolean", "Skip strings.xml/ARSC resources (scan code only)", false),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_xxe_scan",
				"Detect XML External Entity (XXE) injection (MASVS MSTG-PLATFORM / OWASP A05): XML parser factories (DocumentBuilder/SAXParser/XMLInputFactory/Transformer/SchemaFactory/SAXReader/XmlPullParser) instantiated without entity hardening (FEATURE_SECURE_PROCESSING / disallow-doctype-decl / setExpandEntityReferences(false) / external-*-entities / ACCESS_EXTERNAL_*), plus explicit setExpandEntityReferences(true). Evaluates secure-config, unlike serialization-scan",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_intent_redirection_scan",
				"Detect Intent redirection / confused-deputy (CWE-927, Google Play-flagged): a nested Intent extracted from an incoming Intent (getParcelableExtra / getParcelable / Intent.parseUri) then launched (startActivity/startService/sendBroadcast/bindService) or returned via setResult, proxying access to the app's non-exported components. Also flags Intent.parseUri on untrusted data. Not covered by intent-scan",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_cert_pinning_scan",
				"Inventory certificate-pinning posture (MASVS MSTG-NETWORK-4): OkHttp CertificatePinner, raw sha256/sha1 pin literals (with host), TrustKit, a custom X509TrustManager that compares public-key/cert digests (pin-by-pubkey), and Network Security Config <pin-set> domains. The defence-posture inverse of ssl-scan; reports pinsCertificates, mechanisms and pinnedHosts so a review can tell if and how the app resists MITM",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_debug_artifact_scan",
				"Detect debug/instrumentation artifacts left in a release build (MASVS MSTG-CODE-4 / MSTG-RESILIENCE-1): Stetho, Flipper, LeakCanary, Chucker, Chuck, HTTP Inspector, BinderSpy, Android Debug Database, Lynx, Segun-Franko, StrictMode penalties, BuildConfig.DEBUG runtime branches, method-tracing profiler (Debug.startMethodTracing). Distinct from logging-scan (Log API calls) and tamper-detection-scan (anti-hook defences)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_deeplink_scan",
				"Inventory deep-link / app-link attack surface (MASVS MSTG-PLATFORM): manifest <intent-filter> <data> declarations (scheme/host/pathPrefix/pathPattern) with ACTION_VIEW + dynamic deep-link handling in code (Intent.parseUri / ACTION_VIEW / Uri.parse with scheme/host/path). Reports schemes, hosts, exportedDeepLinks count. Distinct from intent-scan and intent-redirection-scan; answers what-to-fuzz for a mobile pentest",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_backup_scan",
				"Audit Android backup configuration (MASVS MSTG-STORAGE-7): allowBackup (adb backup data extraction), fullBackupContent XML rules, BackupAgent subclasses writing sensitive data (SharedPreferences/files/databases) to the backup payload. Distinct from storage-scan (insecure storage APIs); answers can-attacker-pull-data-via-adb-backup",
				optArg("limit", "integer", "Maximum number of findings", 100)));

		tools.add(tool("jadx_screen_capture_scan",
				"Detect screen-capture / screen-recording risks (MASVS MSTG-PLATFORM-4): FLAG_SECURE presence (defence inventory) or absence (screenshot exposure), MediaProjection/VirtualDisplay usage (screen recording capability), PixelCopy/takeScreenshot API usage. Distinct from tapjacking-scan (overlay hijacking) and tamper-detection-scan (anti-hook defences)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_otp_interception_scan",
				"Detect OTP/2FA interception risk across all channels (MASVS MSTG-AUTH-6): SMS OTP body + OTP keywords, NotificationListenerService + OTP keywords, AccessibilityService + OTP keywords, ClipboardManager + OTP keywords, multi-channel OTP interception (2+ channels = spyware indicator). OTP-specific cross of sms-scan/notification-listener-scan/accessibility-scan/clipboard-scan",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_pending_intent_scan",
				"Detect PendingIntent security issues (MASVS MSTG-PLATFORM / CWE-1023): FLAG_MUTABLE usage (attacker can modify wrapped Intent), untrusted fillIn/send with attacker-controlled extras, broadcast/service PendingIntents. Distinct from intent-scan and intent-redirection-scan",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_content_provider_scan",
				"Detect ContentProvider access-control defects (MASVS MSTG-STORAGE-6): unvalidated query/insert/update/delete (no getCallingPackage/getCallingUid check), SQL injection via rawQuery/string concat in query(), path traversal in openFile() via URI path segments. Distinct from exported-provider-scan (manifest inventory) and storage-scan (insecure storage APIs)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_local_auth_bypass_scan",
				"Detect local-authentication bypass patterns (MASVS MSTG-AUTH-8): auth methods returning true unconditionally, hardcoded password/PIN comparisons, BiometricPrompt AuthenticationCallback ignoring result, empty/trivial auth method bodies. Distinct from biometric-scan (API usage inventory)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_unsafe_export_scan",
				"Detect exported components lacking permission protection (MASVS MSTG-PLATFORM): exported Activity/Service/BroadcastReceiver/ContentProvider without android:permission, implicitly exported components (intent-filter without explicit exported attr on API<31). Distinct from manifest-audit and exported-provider-scan",
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_insecure_keystore_scan",
				"Detect insecure Android KeyStore usage (MASVS MSTG-CRYPTO-5): keys without user auth requirement (setUserAuthenticationRequired=false), insecure algorithms in KeyStore context (AES/ECB, RSA/ECB/PKCS1, DES, SHA1), KeyStore with hardcoded password. Distinct from keystore-scan (API inventory) and crypto-scan (generic weak crypto)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_token_storage_scan",
				"Detect insecure token/session storage (MASVS MSTG-STORAGE-1): JWT/OAuth tokens/session cookies in SharedPreferences/files/databases without encryption, plus secure storage inventory (EncryptedSharedPreferences/KeyStore). Distinct from storage-scan (generic insecure storage) and secrets-scan (hardcoded credentials)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_webview_url_scan",
				"Detect WebView URL-source security issues (MASVS MSTG-PLATFORM-2): URLs from Intent extras/data loaded into WebView, open-redirect in shouldOverrideUrlLoading without validation, missing URL whitelist. Distinct from webview-scan (WebView security configuration like JS/file-access/mixed-content)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_insecure_api_scan",
				"Detect insecure Android API usage (MASVS MSTG-CODE-6): component toggle (setComponentEnabledSetting), Settings.Secure/Global reads, DevicePolicyManager misuse, UsageStatsManager surveillance, keyguard dismiss, package install, device identifiers (Build.SERIAL/ANDROID_ID/getDeviceId). Catch-all for patterns not covered by specific scanners",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_network_traffic_scan",
				"Detect network-traffic security issues (MASVS MSTG-NETWORK-1/2): cleartext HTTP URLs, no hostname verification (ALLOW_ALL), insecure OkHttp/Retrofit config (no TLS/pinning), trust-all X509TrustManager, low timeouts. Distinct from ssl-scan (TLS implementation) and network-security-config (NSC policy)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_ad_fraud_scan",
				"Detect ad-fraud / SDK abuse (MASVS MSTG-PRIVACY-3/RESILIENCE-4): click fraud (performClick/clickAd), reward-ad manipulation, advertising ID tracking, device fingerprinting for ad targeting (AppsFlyer/Adjust/Branch/Kochava), hidden ad components, ad SDK inventory (AdMob/Facebook/Unity/AppLovin/IronSource/Vungle/Chartboost/StartApp/InMobi)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_runtime_integrity_scan",
				"Detect runtime integrity self-checks (MASVS MSTG-RESILIENCE-2/3): signature verification at runtime, DEX CRC/checksum, debugger detection (isDebuggerConnected/ptrace), emulator fingerprinting, Frida/Xposed runtime detection. Complements tamper-detection-scan (static markers)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_hardcoded_crypto_scan",
				"Detect hardcoded crypto parameters (MASVS MSTG-CRYPTO-2): fixed IV (IvParameterSpec with literal), static salt (PBEParameterSpec), embedded symmetric keys (SecretKeySpec with string/bytes), hardcoded nonce (GCMParameterSpec), fixed SecureRandom seed. Distinct from crypto-scan (algorithm weakness) and secrets-scan (generic credential leakage)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_permission_request_scan",
				"Audit runtime permission requests (MASVS MSTG-PLATFORM-1): requestPermissions usage, missing shouldShowRequestPermissionRationale, broad permission groups (read+write), check-then-request pattern, onRequestPermissionsResult handling. Complements permission-risk-map (declared permissions)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_data_residue_scan",
				"Detect data surviving app uninstall (MASVS MSTG-STORAGE-8): external storage writes (getExternalStorageDirectory), direct /sdcard/ paths, AccountManager account registration, ContentProvider residue, clipboard sensitive data, sharedUserId in manifest. Distinct from storage-scan (insecure storage) and privacy-scan (PII collection)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_subprocess_scan",
				"Detect subprocess/command execution security issues (MASVS MSTG-CODE-7): Runtime.exec with user input/concatenation, ProcessBuilder with variables, su/sudo privilege escalation, shell execution (sh -c/bash -c). Distinct from command-injection-scan (data-flow taint tracking)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_cryptographic_misuse_scan",
				"Detect cryptographic API misuse (MASVS MSTG-CRYPTO-3/4): ECB mode (AES/DES/ECB), CBC without IV, MD5/SHA-1 for security, weak key sizes (RSA-1024/DES), predictable SecureRandom seed. Distinct from crypto-scan (algorithm inventory) and hardcoded-crypto-scan (hardcoded keys/IVs)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_log_info_leak_scan",
				"Detect sensitive data leaked to logs (MASVS MSTG-STORAGE-3): passwords, tokens, PII (email/phone/SSN), crypto material, auth headers (Authorization/Cookie), intent extras in Log.d/e/i/v/w and System.out. Distinct from logging-scan (framework inventory)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_broadcast_scan",
				"Detect broadcast security issues (MASVS MSTG-PLATFORM): sticky broadcasts (sendStickyBroadcast), implicit broadcast interception, ordered broadcast hijacking (abortBroadcast/getResultData), sensitive data in broadcasts, dynamic receiver leaks, LocalBroadcastManager usage. Distinct from intent-scan and intent-redirection-scan",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_fragment_injection_scan",
				"Detect Fragment injection attacks (MASVS MSTG-PLATFORM): dynamic Fragment from Intent extras (Fragment.instantiate), Fragment from Bundle, Class.forName for Fragment, PreferenceActivity EXTRA_SHOW_FRAGMENT (Android < 4.4), WebView in Fragment. Distinct from intent-redirection-scan and dynamic-loading-scan",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_unsafe_encryption_scan",
				"Detect custom/unsafe encryption (MASVS MSTG-CRYPTO): homemade ciphers (custom encrypt/decrypt), XOR encryption, RC4, DES/3DES/Blowfish, insecure TLS versions (SSLv3/TLS1.0/TLS1.1), custom padding. Distinct from crypto-scan (algorithm inventory), hardcoded-crypto-scan (hardcoded keys), cryptographic-misuse-scan (API misuse like ECB)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_screenshot_leak_scan",
				"Detect screenshot/recent-apps leaks (MASVS MSTG-STORAGE-9/PLATFORM-4): missing FLAG_SECURE on sensitive activities (password/banking/payment), conditional FLAG_SECURE, FLAG_SECURE cleared, sensitive views not cleared in onStop/onDestroy. Distinct from screen-capture-scan (capture API detection)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_trust_boundary_scan",
				"Detect trust boundary violations (MASVS MSTG-PLATFORM/AUTH): Intent extras used for auth/role decisions (isAdmin/isRoot/isAuthenticated), SharedPreferences for auth state, Bundle role checks, unvalidated intent actions, external data in SQL. Distinct from intent-redirection/intent-scan/local-auth-bypass",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_insecure_deeplink_handler_scan",
				"Detect insecure deep-link handler data flows (MASVS MSTG-PLATFORM): path traversal via URI path, SQL injection via query params, WebView loading from deep-link URL, class loading from URI params, auth decisions from deep-link data. Distinct from deeplink-scan (attack surface inventory)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_insecure_file_io_scan",
				"Detect insecure file I/O (MASVS MSTG-STORAGE): MODE_WORLD_READABLE/WRITABLE, sensitive data written unencrypted (password/token/key to file), temp file race conditions, FileProvider misconfiguration, internal file I/O inventory. Distinct from storage-scan and data-residue-scan",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_sms_scan",
				"Scan for SMS interception / abuse (MASVS MSTG-PLATFORM): SMS_RECEIVED interception of OTP message bodies (createFromPdu / getMessageBody), silent SmsManager.sendTextMessage / sendMultipartTextMessage (premium fraud / propagation), abortBroadcast suppression, content://sms inbox reads. Companion to notification-listener-scan as the SMS-based 2FA theft vector",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_notification_listener_scan",
				"Scan for NotificationListenerService abuse (MASVS MSTG-PLATFORM): reads all apps' notifications (onNotificationPosted / getActiveNotifications) for OTP/2FA theft, extracts message body (EXTRA_TEXT / android.text), targets OTP keywords, dismisses fraud-alert notifications. Pairs with accessibility-scan as the banking-trojan credential-theft kit",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_exported_provider_scan",
				"Scan ContentProvider implementations for IPC-reachable vulns (MASVS MSTG-PLATFORM-2): SQL injection (string-concat into query/rawQuery/appendWhere/setTables) and openFile path traversal (URI segment → File with no canonical guard). Provider-scoped and keyed on URI-derived input; pairs with manifest-audit (exported flags)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_keystore_scan",
				"Scan Android Keystore key-protection posture (MASVS MSTG-CRYPTO/STORAGE): keys generated without setUserAuthenticationRequired(true), no StrongBox (setIsStrongBoxBacked), setRandomizedEncryptionRequired(false), legacy BKS/PKCS12/KeyChain providers, null keystore passwords. Distinct from crypto-scan (cipher/hash/RNG misuse) — this is about how keys are protected at rest",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_accessibility_scan",
				"Scan for AccessibilityService abuse (MASVS MSTG-PLATFORM): screen scraping (getRootInActiveWindow / findAccessibilityNodeInfos), cross-app keylogging (TYPE_VIEW_TEXT_CHANGED), and UI automation (performGlobalAction / dispatchGesture / GLOBAL_ACTION_*). A class that both reads the screen and automates the UI is the banking-trojan shape; pairs with tapjacking-scan",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_biometric_scan",
				"Scan for weak biometric auth (MASVS MSTG-AUTH): BiometricPrompt/FingerprintManager.authenticate with NO CryptoObject binding in the class (success is a bare boolean — Frida/tamper bypassable), deprecated FingerprintManager (API<28), and weak/credential fallback (BIOMETRIC_WEAK / setDeviceCredentialAllowed / DEVICE_CREDENTIAL). Reports biometric_crypto_ok when a CryptoObject IS bound",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_dynamic_loading_scan",
				"Scan for dynamic code loading (MASVS MSTG-CODE-9): DexClassLoader/InMemoryDexClassLoader/DexFile, System.load by absolute path, createPackageContext CONTEXT_INCLUDE_CODE. Escalated to high (external_dex_load/external_native_load) when the loaded artefact comes from external/world-writable/network storage (an RCE primitive). Scoped to code-loading classes",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_tapjacking_scan",
				"Scan for tapjacking/overlay exposure (MASVS MSTG-PLATFORM-9): overlay windows (TYPE_APPLICATION_OVERLAY/SYSTEM_ALERT_WINDOW/canDrawOverlays), screen capture (MediaProjection), and presence of the FLAG_SECURE / setFilterTouchesWhenObscured defences. Headline is the boolean summary — an app drawing sensitive UI with neither defence is the tapjacking-exposed case",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_tamper_detection_scan",
				"Locate anti-tampering/anti-analysis defences (MASVS MSTG-RESILIENCE): root detection (su/Magisk/RootBeer), emulator detection (goldfish/qemu/Genymotion), debugger detection (isDebuggerConnected/FLAG_DEBUGGABLE), Frida/Xposed instrumentation detection (port 27042/maps scan/Xposed packages), and SafetyNet/Play Integrity attestation. Dual-use: resilience posture for defenders, bypass-target inventory for RE (pairs with hook/frida). Returns per-category counts + present flags, no severity (these are defences)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_clipboard_scan",
				"Scan code for risky clipboard usage (MASVS MSTG-STORAGE-2): sensitive values copied to the process-global clipboard (setPrimaryClip with password/token/OTP/card), clipboard reads (getPrimaryClip — possible sniffing), and clipboard change listeners (OnPrimaryClipChangedListener — silent surveillance of everything the user copies)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_serialization_scan",
				"Scan code for insecure (de)serialization (MASVS MSTG-PLATFORM/CODE): ObjectInputStream.readObject/readUnshared and XMLDecoder (gadget-chain RCE), Jackson enableDefaultTyping/@JsonTypeInfo polymorphic typing, Serializable/Parcelable read from Intent extras (forgeable by a malicious app), and XML parsers that may be XXE-prone",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_path_traversal_scan",
				"Scan code for path traversal & Zip Slip (MASVS MSTG-CODE/PLATFORM): file sinks (new File/FileInputStream/openFileOutput) fed by untrusted input (intent extras, query params, Uri) without canonicalisation, and archive extraction (ZipInputStream/ZipEntry.getName) written to a File path without a canonical-path guard. Suppressed per-class when a getCanonicalPath/startsWith guard is present",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_command_injection_scan",
				"Scan code for OS command injection (MASVS MSTG-CODE): Runtime.exec/ProcessBuilder whose command is assembled by string concatenation, shell interpreters (sh/bash -c), and su/root-shell invocations. Scoped to process-spawning classes",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_sql_injection_scan",
				"Scan SQLite code for SQL injection (MASVS MSTG-CODE): rawQuery/execSQL/compileStatement/SQLiteDatabase.query whose SQL is assembled by string concatenation instead of ? placeholders + selectionArgs. Scoped to SQLite-touching classes to keep signal high",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_intent_scan",
				"Scan code for insecure Intent/IPC usage (MASVS MSTG-PLATFORM): mutable PendingIntent (missing FLAG_IMMUTABLE — hijackable), sticky broadcasts, implicit sendBroadcast leaks, world-reachable dynamic registerReceiver, implicit Intent construction, URI permission grants",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_storage_scan",
				"Scan code for insecure local data storage (MASVS MSTG-STORAGE): MODE_WORLD_READABLE/WRITEABLE files/prefs/db, sensitive data on shared external storage, unencrypted SharedPreferences (vs EncryptedSharedPreferences) and SQLite (vs SQLCipher), temp files",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 300)));

		tools.add(tool("jadx_network_security_config",
				"Audit the Network Security Config: cleartext traffic permitted, trust of user-installed CAs (MITM risk), certificate pinning presence"));

		tools.add(tool("jadx_adb",
				"Drive a device/emulator via the external adb binary: list devices, install/uninstall, pull an installed package's APK, read logcat, run a shell command",
				optArg("action", "string", "Action: devices, install, uninstall, pull-apk, logcat, shell", "devices"),
				optArg("serial", "string", "Target device serial (adb -s)", null),
				optArg("apk", "string", "APK path (install)", null),
				optArg("package", "string", "Package name (uninstall / pull-apk)", null),
				optArg("out", "string", "Output APK path (pull-apk)", null),
				optArg("args", "string", "Extra arguments for shell/logcat, as one string", null),
				optArg("timeout", "integer", "Tool timeout in milliseconds", 60000)));

		tools.add(tool("jadx_frida",
				"Drive the external Frida toolchain for dynamic instrumentation (the runtime counterpart to jadx_hook): list devices/processes, spawn a package or attach to a process with an injected script, or run frida-trace",
				optArg("action", "string", "Action: list-devices, ps, version, run-script, trace", "list-devices"),
				optArg("package", "string", "Target package to spawn (frida -f); run-script/trace", null),
				optArg("name", "string", "Running process name to attach to (frida -n); run-script/trace", null),
				optArg("script", "string", "Frida JavaScript agent to load (run-script)", null),
				optArg("device", "string", "Frida device id (frida -D); default USB", null),
				optArg("args", "string", "Extra arguments (frida-ps flags / frida-trace patterns), as one string", null),
				optArg("timeout", "integer", "Tool timeout in milliseconds", 60000)));

		tools.add(tool("jadx_apktool",
				"Decode or rebuild an APK with the external apktool binary (full resource round-trip)",
				optArg("action", "string", "Action: decode, build", "decode"),
				optArg("apk", "string", "Input APK (decode) or decoded directory (build)", null),
				optArg("out", "string", "Output directory (decode) or output APK (build)", null),
				optArg("framePath", "string", "Framework files directory (apktool --frame-path)", null),
				optArg("noRes", "boolean", "decode: skip resources", false),
				optArg("noSrc", "boolean", "decode: skip sources/smali", false),
				optArg("timeout", "integer", "Tool timeout in milliseconds", 120000)));

		tools.add(tool("jadx_sdk_inventory",
				"Inventory third-party SDKs and libraries embedded in the APK (analytics, ads, crash reporting, messaging, payment, social, tracking, utility)",
				optArg("categories", "string", "Comma-separated categories: analytics,ads,crash,messaging,payment,social,utility,tracking,all", "all"),
				optArg("limit", "integer", "Maximum SDK findings", 100)));

		tools.add(tool("jadx_bypass_hook",
				"Generate Frida bypass scripts for detected Android security protections (root, emulator, debugger, SSL pinning, integrity, device spoof)",
				optArg("package", "string", "Target app package name", null),
				optArg("types", "string", "Bypass types: root,emulator,debugger,ssl-pinning,integrity,spoof,all", "all"),
				optArg("scan", "boolean", "Scan APK for protections before generating", true)));

		tools.add(tool("jadx_packer_detect",
				"Detect app packers and protection wrappers (360 Jiagu, Tencent Legu, Baidu, Bangcle, ijiami, Naga, etc.)",
				optArg("limit", "integer", "Maximum findings", 20)));

		tools.add(tool("jadx_capability_report",
				"Generate a high-level capability summary of the APK — what the app does at a glance",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("top", "integer", "Top N items per category", 20)));

		tools.add(tool("jadx_native_lib_security",
				"Security-check native .so libraries embedded in the APK (ELF analysis: NX, PIE, RELRO, canary, crypto constants)",
				optArg("limit", "integer", "Maximum libraries to analyze", 50)));
		tools.add(tool("jadx_jni_binding_audit",
				"Cross-reference Java native methods against real .so Java_* exports (.dynsym) to reveal static bindings vs RegisterNatives-hidden natives",
				optArg("package", "string", "Only audit classes under this package prefix", null),
				optArg("limit", "integer", "Maximum native methods to audit", 1000)));
		tools.add(tool("jadx_api_endpoint_extract",
				"Extract API endpoints from Retrofit annotations, OkHttp usage, and URL literals in decompiled code",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum endpoints to return", 200)));
		tools.add(tool("jadx_google_services_config",
				"Extract Google/Firebase service configuration from APK resources and decompiled code",
				optArg("limit", "integer", "Maximum findings", 100)));
		tools.add(tool("jadx_dangerous_api_map",
				"Map dangerous Android permissions to actual API calls used in the APK code",
				optArg("app_only", "boolean", "Exclude framework/library callers", true),
				optArg("limit", "integer", "Maximum findings per permission", 50)));
		tools.add(tool("jadx_manifest_security_audit",
				"Comprehensive manifest security audit with risk scoring (security flags, dangerous permissions, exported components)",
				optArg("limit", "integer", "Maximum findings per category", 50)));
		tools.add(tool("jadx_il2cpp_metadata_scan",
				"Scan Unity IL2CPP global-metadata.dat from APK resources for C# class/method/field identifiers",
				optArg("limit", "integer", "Maximum identifiers to return", 500)));
		tools.add(tool("jadx_flutter_analysis",
				"Analyze Flutter/Dart APK structure: detect Flutter version, snapshot files, Dart widget identifiers",
				optArg("limit", "integer", "Maximum identifiers to return", 200)));
		tools.add(tool("jadx_react_native_analysis",
				"Analyze a React Native APK: detect Hermes bytecode vs plaintext JS bundle, read the Hermes bytecode version, and scan index.android.bundle bytes for secrets and cleartext URLs that Java-only scanners miss",
				optArg("min_entropy", "number", "Min Shannon entropy for generic secret detection in the bundle", 4.0),
				optArg("limit", "integer", "Maximum secrets/URLs to return", 200)));
		tools.add(tool("jadx_source_quality_report",
				"Evaluate decompiled code quality: error markers, stubs, obfuscation indicators, catch-all handlers",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum classes to report", 50)));
		tools.add(tool("jadx_class_inventory",
				"Inventory of classes, methods, and fields grouped by package",
				optArg("package", "string", "Only include classes under this package prefix", null),
				optArg("top", "integer", "Top N packages by class count", 20)));
		tools.add(tool("jadx_entrypoint_scan",
				"Discover APK entry points (Application, Activities, Providers, Receivers, Services, static inits, JNI loads)",
				optArg("limit", "integer", "Maximum entry points per category", 50)));
		tools.add(tool("jadx_dex_stat",
				"DEX-level statistics: class/method/field counts, multidex detection, package distribution",
				optArg("top", "integer", "Top N packages by class count", 15)));
		tools.add(tool("jadx_custom_permission_audit",
				"Audit custom <permission> declarations: protectionLevel, whether they guard sensitive exported components, and misconfigurations (normal-level, unenforced, deprecated signatureOrSystem)",
				optArg("limit", "integer", "Maximum permissions to report", 100)));
		tools.add(tool("jadx_apk_signature",
				"Parse APK signing certificates and signature schemes (v1 JAR + v2/v3 signing block): subject/issuer, validity, signature algorithm, SHA-1/SHA-256 fingerprints"));
		tools.add(tool("jadx_dead_code_report",
				"Detect orphaned public classes never referenced by any other class (dead-code candidates)",
				optArg("limit", "integer", "Maximum orphan candidates to report", 50)));
		tools.add(tool("jadx_method_complexity",
				"Per-method cyclomatic complexity (decision-point count) over decompiled source — finds the long branchy methods where bugs hide",
				optArg("top", "integer", "Top N most complex methods to report", 30),
				optArg("threshold", "integer", "Complexity threshold for a complex method", 10),
				optArg("package", "string", "Only scan classes under this package prefix", null)));
		tools.add(tool("jadx_resource_inventory",
				"Inventory APK resources by category (res/ subdirs, assets, lib, META-INF, dex) with counts and extensions"));
		tools.add(tool("jadx_shared_uid_audit",
				"Detect android:sharedUserId in the manifest and assess shared-UID data/privilege risk (deprecated since Android 10)"));
		tools.add(tool("jadx_device_admin_scan",
				"Scan for DeviceAdminReceiver + DevicePolicyManager dangerous APIs (lockNow/wipeData/resetPassword) and manifest <device-admin> policies",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));
		tools.add(tool("jadx_vpn_service_scan",
				"Scan for VpnService subclasses + Builder.establish/addRoute (full traffic interception capability) and manifest BIND_VPN_SERVICE",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));
		tools.add(tool("jadx_nfc_scan",
				"Scan for NFC intent handling + Ndef read/write + foreground dispatch (NFC attack surface)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));
		tools.add(tool("jadx_sensor_scan",
				"Scan for sensor side-channels (SensorManager.registerListener, accelerometer/gyro/proximity, high sampling rate, always-on listeners)",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));
		tools.add(tool("jadx_alarm_wakelock_scan",
				"Scan for background persistence: AlarmManager repeating/Doze-bypass alarms, PARTIAL_WAKE_LOCK, BOOT_COMPLETED auto-start",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_bluetooth_scan",
				"Scan for Bluetooth capability: adapter/gatt/socket, BLE scan, inbound server socket, BLUETOOTH_* permissions",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_account_scan",
				"Scan for AccountManager: account enumeration, auth-token access (peekAuthToken/setAuthToken), custom Authenticator, ContentResolver sync",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_location_scan",
				"Scan for location acquisition (LocationManager GPS/NETWORK/PASSIVE, FusedLocationProviderClient, Geocoder) and mock-location anti-spoof checks",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_sim_info_scan",
				"Scan for SIM/carrier/device-identifier reads: TelephonyManager getSimSerialNumber/getSubscriberId/getDeviceId/getLine1Number, SubscriptionManager",
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of findings", 200)));

		tools.add(tool("jadx_smali",
				"Render smali (Dalvik bytecode) for a class or a single method (ground truth below jadx Java)",
				arg("class", "string", "Full class name", null),
				optArg("method", "string", "Method short ID (e.g. onCreate(Landroid/os/Bundle;)V) to render only that method", null),
				optArg("max-chars", "integer", "Cap smali output length", 200000)));

		tools.add(tool("jadx_find_classes",
				"Find classes by superclass, implemented interface, or @annotation (structured type-hierarchy query)",
				arg("by", "string", "Query dimension: super, interface, annotation", null),
				arg("query", "string", "Target super/interface/annotation name", null),
				optArg("exact", "boolean", "Exact name match instead of substring", false),
				optArg("ignore-case", "boolean", "Case-insensitive matching", false),
				optArg("package", "string", "Only match classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of matches", 100)));

		tools.add(tool("jadx_string_xref",
				"Find classes/methods that embed a given string literal (reverse string lookup)",
				arg("query", "string", "String literal to locate (repeatable; pass multiple via array)", null),
				optArg("exact", "boolean", "Exact literal match instead of substring", false),
				optArg("ignore-case", "boolean", "Case-insensitive matching", false),
				optArg("package", "string", "Only scan classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of references", 200)));

		tools.add(tool("jadx_call_sites",
				"Find all call sites of a given API method name across the APK (incl. external framework APIs)",
				arg("method", "string", "API method name to locate (e.g. getDeviceId)", null),
				optArg("class", "string", "Only count calls whose receiver type contains this name", null),
				optArg("package", "string", "Only scan caller classes under this package prefix", null),
				optArg("limit", "integer", "Maximum number of call sites", 200)));

		return tools;
	}

	private static Map<String, Object> arg(String name, String type, String desc, Object defaultValue) {
		Map<String, Object> param = new LinkedHashMap<>();
		param.put("name", name);
		param.put("type", type);
		param.put("description", desc);
		if (defaultValue != null) {
			param.put("default", defaultValue);
		}
		param.put("required", true);
		return param;
	}

	private static Map<String, Object> optArg(String name, String type, String desc, Object defaultValue) {
		Map<String, Object> param = new LinkedHashMap<>();
		param.put("name", name);
		param.put("type", type);
		param.put("description", desc);
		if (defaultValue != null) {
			param.put("default", defaultValue);
		}
		param.put("required", false);
		return param;
	}

	@SafeVarargs
	private static Map<String, Object> tool(String name, String desc, Map<String, Object>... params) {
		Map<String, Object> toolDef = new LinkedHashMap<>();
		toolDef.put("name", name);
		toolDef.put("description", desc);

		Map<String, Object> properties = new LinkedHashMap<>();
		List<String> required = new ArrayList<>();

		for (Map<String, Object> param : params) {
			String paramName = (String) param.get("name");
			String paramType = (String) param.get("type");
			String paramDesc = (String) param.get("description");
			boolean isRequired = Boolean.TRUE.equals(param.get("required"));

			Map<String, Object> propDef = new LinkedHashMap<>();
			propDef.put("type", paramType);
			propDef.put("description", paramDesc);
			if (param.containsKey("default")) {
				propDef.put("default", param.get("default"));
			}
			properties.put(paramName, propDef);

			if (isRequired) {
				required.add(paramName);
			}
		}

		Map<String, Object> inputSchema = new LinkedHashMap<>();
		inputSchema.put("type", "object");
		inputSchema.put("properties", properties);
		if (!required.isEmpty()) {
			inputSchema.put("required", required);
		}

		toolDef.put("inputSchema", inputSchema);
		return toolDef;
	}
}
