package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Generates ready-to-use Frida bypass scripts for common Android security protections.
 * Absorbs the bypass hook generation design from {@code droid-re-chain}'s
 * {@code tools_bypass.py} (root/emulator/debugger/integrity/device-spoof hooks) and
 * enriches it with code-context-aware detection: it first scans the APK to confirm which
 * protections are actually present, then generates targeted bypass scripts for the detected
 * ones only. Native capability — reads jadx's parsed model to emit Frida JavaScript.
 */
@Command(name = "bypass-hook", description = "Generate Frida bypass scripts for detected security protections")
public class BypassHookCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Target app package name (for hook injection)")
	protected String packageName;

	@Option(names = { "--types" }, description = "Bypass types: root,emulator,debugger,ssl-pinning,integrity,spoof,all", defaultValue = "all")
	protected String types = "all";

	@Option(names = { "--scan" }, description = "Scan APK code for protections before generating (default: true)", defaultValue = "true")
	protected boolean scan = true;

	/** Detection patterns per bypass type. */
	private static final class DetectPattern {
		final String bypassType;
		final String[] patterns;

		DetectPattern(String bypassType, String[] patterns) {
			this.bypassType = bypassType;
			this.patterns = patterns;
		}
	}

	private static final List<DetectPattern> DETECTIONS = List.of(
			new DetectPattern("root", new String[] {
					"/su", "/sbin/su", "/system/bin/su", "/system/xbin/su",
					"Superuser.apk", "com.noshufou.android.su",
					"eu.chainfire.supersu", "com.koushikdutta.superuser",
					"RootBeer", "isRooted", "checkRoot", "detectRoot"
			}),
			new DetectPattern("emulator", new String[] {
					"genymotion", "goldfish", "sdk_gphone", "emulator",
					"Build.FINGERPRINT", "isEmulator", "detectEmulator",
					"com.google.android.launcher.layouts.genymotion"
			}),
			new DetectPattern("debugger", new String[] {
					"isDebuggerConnected", "android.os.Debug",
					"ptrace", "TracerPid", "antiDebug", "checkDebugger"
			}),
			new DetectPattern("ssl-pinning", new String[] {
					"X509TrustManager", "checkServerTrusted", "TrustManager",
					"CertificatePinner", "ssl-pinning", "PinningTrustManager",
					"OkHttpCertPin", "CertificatePinner.Builder",
					"net.ssl", "SSLSocketFactory"
			}),
			new DetectPattern("integrity", new String[] {
					"getPackageInfo", "PackageInfo", "signatures",
					"IntegrityCheck", "verifySignature", "checkSignature",
					"PlayIntegrity", "AppCheck", "SafetyNet",
					"com.google.android.play.core.integrity"
			}),
			new DetectPattern("spoof", new String[] {
					"Build.MODEL", "Build.MANUFACTURER", "Build.DEVICE",
					"getDeviceId", "TelephonyManager", "IMEI",
					"ANDROID_ID", "Settings.Secure"
			}));

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageName = (String) args.get("package");
		if (args.get("types") != null) {
			this.types = (String) args.get("types");
		}
		if (args.containsKey("scan")) {
			this.scan = Boolean.TRUE.equals(args.get("scan"));
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<String> wantTypes = new ArrayList<>();
		if ("all".equals(types)) {
			wantTypes.add("all");
		} else {
			for (String t : types.split(",")) {
				wantTypes.add(t.trim().toLowerCase());
			}
		}

		// If scan mode, detect which protections are actually present.
		Map<String, Boolean> detected = new LinkedHashMap<>();
		if (scan) {
			for (JavaClass cls : decompiler.getClasses()) {
				String code;
				try {
					code = cls.getCode();
				} catch (Exception e) {
					continue;
				}
				if (code == null || code.isEmpty()) {
					continue;
				}
				for (DetectPattern dp : DETECTIONS) {
					if (detected.containsKey(dp.bypassType)) {
						continue;
					}
					if (!wantTypes.contains("all") && !wantTypes.contains(dp.bypassType)) {
						continue;
					}
					for (String pat : dp.patterns) {
						if (code.contains(pat)) {
							detected.put(dp.bypassType, true);
							break;
						}
					}
				}
				if (detected.size() == DETECTIONS.size()) {
					break;
				}
			}
		} else {
			// Without scan, generate all requested types.
			for (DetectPattern dp : DETECTIONS) {
				if (wantTypes.contains("all") || wantTypes.contains(dp.bypassType)) {
					detected.put(dp.bypassType, true);
				}
			}
		}

		// Infer package name from code if not provided.
		if (packageName == null || packageName.isEmpty()) {
			for (JavaClass cls : decompiler.getClasses()) {
				String name = cls.getFullName();
				if (!name.startsWith("android.") && !name.startsWith("androidx.")
						&& !name.startsWith("java.") && !name.startsWith("kotlin.")
						&& !name.startsWith("com.google.")) {
					int dot = name.indexOf('.', name.indexOf('.') + 1);
					if (dot > 0) {
						int dot2 = name.indexOf('.', dot + 1);
						if (dot2 > 0) {
							packageName = name.substring(0, dot2);
							break;
						}
					}
				}
			}
		}

		String pkg = packageName != null ? packageName : "com.example.target";

		// Generate scripts for detected types.
		List<Map<String, Object>> scripts = new ArrayList<>();
		if (detected.getOrDefault("root", false)) {
			scripts.add(script("root_detection_bypass", generateRootBypass(pkg)));
		}
		if (detected.getOrDefault("emulator", false)) {
			scripts.add(script("emulator_detection_bypass", generateEmulatorBypass()));
		}
		if (detected.getOrDefault("debugger", false)) {
			scripts.add(script("debugger_detection_bypass", generateDebuggerBypass()));
		}
		if (detected.getOrDefault("ssl-pinning", false)) {
			scripts.add(script("ssl_pinning_bypass", generateSslPinningBypass()));
		}
		if (detected.getOrDefault("integrity", false)) {
			scripts.add(script("integrity_check_bypass", generateIntegrityBypass(pkg)));
		}
		if (detected.getOrDefault("spoof", false)) {
			scripts.add(script("device_spoof", generateDeviceSpoof()));
		}

		List<String> notes = new ArrayList<>();
		notes.add("Launch with: frida -U -f " + pkg + " -l <script.js> --no-pause");
		if (scripts.isEmpty()) {
			notes.add("No security protections detected. Use --types=all --scan=false to generate all bypass scripts anyway.");
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("scripts", scripts);
		data.put("detectedProtections", new ArrayList<>(detected.keySet()));
		data.put("package", pkg);
		data.put("notes", notes);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> script(String type, String code) {
		Map<String, Object> s = new LinkedHashMap<>();
		s.put("type", type);
		s.put("language", "javascript");
		s.put("engine", "frida");
		s.put("script", code);
		return s;
	}

	// ─── Bypass script generators (absorbed from droid-re-chain tools_bypass.py) ──

	private static String generateRootBypass(String pkg) {
		return "'use strict';\n"
				+ "Java.perform(function() {\n"
				+ "    // Hook File.exists to hide su binaries\n"
				+ "    var File = Java.use('java.io.File');\n"
				+ "    File.exists.implementation = function() {\n"
				+ "        var path = this.getPath();\n"
				+ "        var rootPaths = ['/su', '/sbin/su', '/system/bin/su', '/system/xbin/su',\n"
				+ "                         '/data/local/tmp/su', '/system/app/Superuser.apk',\n"
				+ "                         '/system/xbin/daemonsu', '/sbin/.magisk'];\n"
				+ "        for (var i = 0; i < rootPaths.length; i++) {\n"
				+ "            if (path.indexOf(rootPaths[i]) >= 0) {\n"
				+ "                console.log('[bypass] Blocked root check: ' + path);\n"
				+ "                return false;\n"
				+ "            }\n"
				+ "        }\n"
				+ "        return this.exists();\n"
				+ "    };\n"
				+ "    // Hide test-keys in Build.TAGS\n"
				+ "    var Build = Java.use('android.os.Build');\n"
				+ "    try { Build.TAGS.value = 'release-keys'; } catch(e) {}\n"
				+ "    console.log('[bypass] Root detection hooks installed for " + pkg + "');\n"
				+ "});\n";
	}

	private static String generateEmulatorBypass() {
		return "'use strict';\n"
				+ "Java.perform(function() {\n"
				+ "    var Build = Java.use('android.os.Build');\n"
				+ "    Build.MODEL.value = 'Pixel 8 Pro';\n"
				+ "    Build.DEVICE.value = 'husky';\n"
				+ "    Build.PRODUCT.value = 'husky';\n"
				+ "    Build.MANUFACTURER.value = 'Google';\n"
				+ "    Build.BRAND.value = 'google';\n"
				+ "    Build.HARDWARE.value = 'husky';\n"
				+ "    Build.FINGERPRINT.value = 'google/husky/husky:14/AP2A.240905.003/12231197:user/release-keys';\n"
				+ "    Build.TAGS.value = 'release-keys';\n"
				+ "    Build.TYPE.value = 'user';\n"
				+ "    // Hook TelephonyManager for device ID\n"
				+ "    try {\n"
				+ "        var TelephonyManager = Java.use('android.telephony.TelephonyManager');\n"
				+ "        TelephonyManager.getDeviceId.overload().implementation = function() {\n"
				+ "            return '352756100123456';\n"
				+ "        };\n"
				+ "    } catch(e) {}\n"
				+ "    console.log('[bypass] Emulator detection hooks installed');\n"
				+ "});\n";
	}

	private static String generateDebuggerBypass() {
		return "'use strict';\n"
				+ "Java.perform(function() {\n"
				+ "    // Hook Debug.isDebuggerConnected\n"
				+ "    var Debug = Java.use('android.os.Debug');\n"
				+ "    Debug.isDebuggerConnected.implementation = function() { return false; };\n"
				+ "    // Hook native ptrace\n"
				+ "    var ptracePtr = Module.findExportByName('libc.so', 'ptrace');\n"
				+ "    if (ptracePtr) {\n"
				+ "        Interceptor.attach(ptracePtr, {\n"
				+ "            onEnter: function(args) {\n"
				+ "                var request = args[0].toInt32();\n"
				+ "                if (request === 0 || request === 16 || request === 17) {\n"
				+ "                    console.log('[bypass] Blocked ptrace call: ' + request);\n"
				+ "                    this.returnValue = 0;\n"
				+ "                }\n"
				+ "            }\n"
				+ "        });\n"
				+ "    }\n"
				+ "    console.log('[bypass] Debugger detection hooks installed');\n"
				+ "});\n";
	}

	private static String generateSslPinningBypass() {
		return "'use strict';\n"
				+ "Java.perform(function() {\n"
				+ "    // Hook TrustManager to accept all certificates\n"
				+ "    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');\n"
				+ "    var SSLContext = Java.use('javax.net.ssl.SSLContext');\n"
				+ "    var TrustManagerImpl = Java.registerClass({\n"
				+ "        name: 'com.bypass.TrustManager',\n"
				+ "        implements: [TrustManager],\n"
				+ "        methods: {\n"
				+ "            checkClientTrusted: function(chain, authType) {},\n"
				+ "            checkServerTrusted: function(chain, authType) {},\n"
				+ "            getAcceptedIssuers: function() { return []; }\n"
				+ "        }\n"
				+ "    });\n"
				+ "    // Override SSLContext.init to use our trust manager\n"
				+ "    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')\n"
				+ "        .implementation = function(km, tm, sr) {\n"
				+ "            this.init(km, [TrustManagerImpl.$new()], sr);\n"
				+ "        };\n"
				+ "    // Hook OkHttp CertificatePinner\n"
				+ "    try {\n"
				+ "        var CertificatePinner = Java.use('okhttp3.CertificatePinner');\n"
				+ "        CertificatePinner.check.overload('java.lang.String', 'java.util.List')\n"
				+ "            .implementation = function(hostname, peerCertificates) {\n"
				+ "                console.log('[bypass] OkHttp SSL pinning bypassed for: ' + hostname);\n"
				+ "            };\n"
				+ "    } catch(e) {}\n"
				+ "    console.log('[bypass] SSL pinning hooks installed');\n"
				+ "});\n";
	}

	private static String generateIntegrityBypass(String pkg) {
		return "'use strict';\n"
				+ "Java.perform(function() {\n"
				+ "    // Hook PackageManager.getPackageInfo to return consistent signatures\n"
				+ "    var PackageManager = Java.use('android.app.ApplicationPackageManager');\n"
				+ "    PackageManager.getPackageInfo.overload('java.lang.String', 'int')\n"
				+ "        .implementation = function(packageName, flags) {\n"
				+ "            var info = this.getPackageInfo(packageName, flags);\n"
				+ "            console.log('[bypass] getPackageInfo called for: ' + packageName);\n"
				+ "            return info;\n"
				+ "        };\n"
				+ "    // Hook Signature.hashCode to return consistent value\n"
				+ "    try {\n"
				+ "        var Signature = Java.use('android.content.pm.Signature');\n"
				+ "        Signature.hashCode.implementation = function() {\n"
				+ "            return 0xDEADBEEF;\n"
				+ "        };\n"
				+ "    } catch(e) {}\n"
				+ "    // Hook Arrays.equals to bypass signature comparison\n"
				+ "    try {\n"
				+ "        var Arrays = Java.use('java.util.Arrays');\n"
				+ "        Arrays.equals.overload('[B', '[B').implementation = function(a, b) {\n"
				+ "            console.log('[bypass] Signature comparison bypassed');\n"
				+ "            return true;\n"
				+ "        };\n"
				+ "    } catch(e) {}\n"
				+ "    console.log('[bypass] Integrity check hooks installed for " + pkg + "');\n"
				+ "});\n";
	}

	private static String generateDeviceSpoof() {
		return "'use strict';\n"
				+ "Java.perform(function() {\n"
				+ "    var Build = Java.use('android.os.Build');\n"
				+ "    Build.MANUFACTURER.value = 'Google';\n"
				+ "    Build.MODEL.value = 'Pixel 8 Pro';\n"
				+ "    Build.DEVICE.value = 'husky';\n"
				+ "    Build.PRODUCT.value = 'husky';\n"
				+ "    Build.HARDWARE.value = 'husky';\n"
				+ "    Build.BRAND.value = 'google';\n"
				+ "    Build.FINGERPRINT.value = 'google/husky/husky:14/AP2A.240905.003/12231197:user/release-keys';\n"
				+ "    Build.TAGS.value = 'release-keys';\n"
				+ "    // Hook Settings.Secure for ANDROID_ID\n"
				+ "    try {\n"
				+ "        var Settings = Java.use('android.provider.Settings$Secure');\n"
				+ "        Settings.getString.overload('android.content.ContentResolver', 'java.lang.String')\n"
				+ "            .implementation = function(resolver, name) {\n"
				+ "                if ('android_id'.equals(name)) {\n"
				+ "                    return 'a1b2c3d4e5f67890';\n"
				+ "                }\n"
				+ "                return this.getString(resolver, name);\n"
				+ "            };\n"
				+ "    } catch(e) {}\n"
				+ "    console.log('[spoof] Device fingerprint spoofed to Google Pixel 8 Pro');\n"
				+ "});\n";
	}

	@Override
	protected String getDaemonCommandName() {
		return "bypass-hook";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		if (packageName != null) {
			args.put("package", packageName);
		}
		args.put("types", types);
		args.put("scan", scan);
		return args;
	}
}
