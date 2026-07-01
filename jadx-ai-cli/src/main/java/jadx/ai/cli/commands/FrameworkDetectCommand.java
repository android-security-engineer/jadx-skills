package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;

/**
 * Identifies the cross-platform / app framework an APK was built with — the triage step that
 * decides which specialist tool you reach for next (jadx for native Java/Kotlin, blutter/reFlutter
 * for Flutter, Il2CppDumper for Unity, a .NET disassembler for Xamarin). JADX only fully recovers
 * the Java/Kotlin layer; for a Flutter or Unity app the real logic lives in {@code libapp.so} /
 * {@code libil2cpp.so} + {@code global-metadata.dat}, and the Java you see is a thin shell. This
 * command absorbs that "what am I even looking at?" detection in-process: it matches framework
 * signatures across resource paths (the cheap, reliable signal: bundled {@code .so} names, asset
 * directories, packaged assemblies) and class-name prefixes (no decompilation needed), and reports
 * each framework with the concrete evidence that fired.
 *
 * Returns {@code {frameworks:[{name,confidence,evidence:[...]}], primary, isCrossPlatform}}.
 */
@Command(name = "framework-detect",
		description = "Detect the app framework (Flutter, React Native, Unity/il2cpp, Xamarin/.NET, Cordova, ...) from .so/asset/class signatures")
public class FrameworkDetectCommand extends AbstractCommand {

	/** A framework signature: substrings to look for in resource paths and class names. */
	private static final class Sig {
		final String name;
		final String[] resourceMarkers;
		final String[] classPrefixes;
		final String versionClass;      // Class to scan for version string
		final String versionPattern;    // Regex to extract version

		Sig(String name, String[] resourceMarkers, String[] classPrefixes) {
			this(name, resourceMarkers, classPrefixes, null, null);
		}

		Sig(String name, String[] resourceMarkers, String[] classPrefixes,
				String versionClass, String versionPattern) {
			this.name = name;
			this.resourceMarkers = resourceMarkers;
			this.classPrefixes = classPrefixes;
			this.versionClass = versionClass;
			this.versionPattern = versionPattern;
		}
	}

	private static final List<Sig> SIGNATURES = List.of(
			new Sig("Flutter",
					new String[] { "libflutter.so", "libapp.so", "flutter_assets/", "/flutter_assets" },
					new String[] { "io.flutter." },
					"io.flutter.view.FlutterMain",
					"Flutter\\s+(\\d+\\.\\d+\\.\\d+)"),
			new Sig("React Native",
					new String[] { "libreactnativejni.so", "libhermes.so", "index.android.bundle", "libjsc.so" },
					new String[] { "com.facebook.react." },
					"com.facebook.react.BuildConfig",
					"VERSION_NAME\\s*=\\s*\"([^\"]+)\""),
			new Sig("Unity (IL2CPP)",
					new String[] { "libil2cpp.so", "global-metadata.dat", "libunity.so" },
					new String[] { "com.unity3d." }),
			new Sig("Unity (Mono)",
					new String[] { "libmonobdwgc-2.0.so", "libmono", "/Managed/", "assets/bin/Data" },
					new String[] { "com.unity3d." }),
			new Sig("Xamarin / .NET",
					new String[] { "libmonodroid.so", "libxamarin-app.so", "assemblies/", "libmonosgen" },
					new String[] { "mono.", "crc64", "md5" }),
			new Sig("Cordova / PhoneGap",
					new String[] { "assets/www/cordova.js", "www/cordova_plugins.js", "config.xml" },
					new String[] { "org.apache.cordova." }),
			new Sig("Ionic / Capacitor",
					new String[] { "assets/public/", "capacitor.config.json", "assets/capacitor.plugins.json" },
					new String[] { "com.getcapacitor." }),
			new Sig("NativeScript",
					new String[] { "libNativeScript.so", "assets/app/", "assets/metadata/" },
					new String[] { "com.tns." }),
			new Sig("Qt",
					new String[] { "libQt5Core", "libQt6Core", "libgnustl_shared.so", "android_main" },
					new String[] { "org.qtproject." }),
			new Sig("Kotlin",
					new String[] { "kotlin/kotlin.kotlin_builtins", "META-INF/kotlin" },
					new String[] { "kotlin." }),
			// ── Additional frameworks absorbed from mobile-security-mcp frameworks-detector ──
			new Sig("Kony",
					new String[] { "libkonyjs.so", "libkwik.so", "assets/js/" },
					new String[] { "com.kony." }),
			new Sig("Appcelerator Titanium",
					new String[] { "libti.so", "assets/titanium/" },
					new String[] { "org.appcelerator." }),
			new Sig("Corona / Solar2D",
					new String[] { "libcorona.so", "corona.cfg", "resource.car" },
					new String[] { "com.ansca.corona.", "com.coronalabs." }),
			new Sig("Cocos2d-x",
					new String[] { "libcocos2dlua.so", "libcocos2djs.so", "libcocos2dcpp.so",
							"assets/src/", "assets/res/" },
					new String[] { "org.cocos2dx." }),
			new Sig("Unreal Engine",
					new String[] { "libUE4.so", "libUnreal.so", "UE4CommandLine.txt" },
					new String[] { "com.epicgames." }),
			new Sig("Adobe AIR",
					new String[] { "libair.so", "assets/air/", "META-INF/AIR" },
					new String[] { "com.adobe.air." }),
			new Sig("PhoneGap Build",
					new String[] { "phonegap.js", "assets/www/phonegap.js" },
					new String[] { "com.phonegap." }),
			new Sig("Weex",
					new String[] { "libweexcore.so", "libweexjs.so" },
					new String[] { "com.taobao.weex." }),
			new Sig("Lazarus / Free Pascal",
					new String[] { "liblcl.so", "liblclapp.so", "libpas2js.so" },
					new String[] { "org.lazarus." }),
			new Sig("Tauri",
					new String[] { "libtauri.so", "tauri.conf.json" },
					new String[] { "app.tauri." }));

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		// Gather resource paths once.
		List<String> resourceNames = new ArrayList<>();
		for (ResourceFile res : decompiler.getResources()) {
			String n = res.getOriginalName();
			if (n != null) {
				resourceNames.add(n.replace('\\', '/'));
			}
		}
		// Gather class names once (cheap — no getCode()).
		List<String> classNames = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			classNames.add(cls.getFullName());
		}

		// Build a class→code map for version detection (lazy — only populated if needed)
		Map<String, String> codeCache = null;

		List<Map<String, Object>> frameworks = new ArrayList<>();
		for (Sig sig : SIGNATURES) {
			List<String> evidence = new ArrayList<>();
			int resourceHits = 0;
			for (String marker : sig.resourceMarkers) {
				for (String rn : resourceNames) {
					if (rn.contains(marker)) {
						evidence.add("resource:" + marker);
						resourceHits++;
						break;
					}
				}
			}
			boolean classHit = false;
			for (String prefix : sig.classPrefixes) {
				for (String cn : classNames) {
					if (cn.startsWith(prefix)) {
						evidence.add("class:" + prefix + "*");
						classHit = true;
						break;
					}
				}
			}
			if (evidence.isEmpty()) {
				continue;
			}
			// A bundled .so / metadata file is a strong signal; a class prefix alone is weaker
			// (Kotlin stdlib, or a stray copied package). Require either a resource hit or treat
			// class-only as "low".
			String confidence;
			if (resourceHits >= 2 || (resourceHits >= 1 && classHit)) {
				confidence = "high";
			} else if (resourceHits == 1 || classHit) {
				confidence = "medium";
			} else {
				confidence = "low";
			}
			Map<String, Object> fw = new LinkedHashMap<>();
			fw.put("name", sig.name);
			fw.put("confidence", confidence);
			fw.put("evidence", evidence);

			// ── Version detection ──
			if (sig.versionClass != null && sig.versionPattern != null) {
				String version = detectVersion(decompiler, classNames, sig.versionClass, sig.versionPattern, codeCache);
				if (version != null) {
					fw.put("version", version);
				}
			}

			frameworks.add(fw);
		}

		// Primary = the highest-confidence non-Kotlin framework (Kotlin is a language, not a
		// cross-platform shell, so it never wins the "what built this" question on its own).
		String primary = null;
		String bestConf = null;
		boolean crossPlatform = false;
		for (Map<String, Object> fw : frameworks) {
			String name = (String) fw.get("name");
			String conf = (String) fw.get("confidence");
			boolean isCp = !name.equals("Kotlin");
			if (isCp && isBetter(conf, bestConf)) {
				primary = name;
				bestConf = conf;
			}
			if (isCp && (conf.equals("high") || conf.equals("medium"))) {
				crossPlatform = true;
			}
		}
		if (primary == null) {
			primary = "Native (Java/Kotlin)";
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("frameworks", frameworks);
		data.put("primary", primary);
		data.put("isCrossPlatform", crossPlatform);
		return JsonOutput.ok(data);
	}

	private static boolean isBetter(String conf, String best) {
		return rank(conf) > rank(best);
	}

	private static int rank(String conf) {
		if (conf == null) {
			return -1;
		}
		switch (conf) {
			case "high":
				return 3;
			case "medium":
				return 2;
			case "low":
				return 1;
			default:
				return 0;
		}
	}
	/**
	 * Attempt to extract a framework version string from a known class.
	 * Scans the target class code for the version pattern.
	 */
	private static String detectVersion(JadxDecompiler decompiler,
			List<String> classNames, String targetClass,
			String versionPattern, Map<String, String> codeCache) {
		Pattern vp = Pattern.compile(versionPattern);
		// Find the class
		for (JavaClass cls : decompiler.getClasses()) {
			if (cls.getFullName().equals(targetClass)) {
				String code;
				try {
					code = cls.getCode();
				} catch (Exception e) {
					return null;
				}
				if (code == null) return null;
				Matcher m = vp.matcher(code);
				if (m.find()) {
					return m.group(1);
				}
				return null;
			}
		}
		// Also try BuildConfig variant: com.foo.BuildConfig
		String buildConfig = targetClass.replaceAll("\\.[^.]+$", ".BuildConfig");
		for (JavaClass cls : decompiler.getClasses()) {
			if (cls.getFullName().equals(buildConfig)) {
				String code;
				try {
					code = cls.getCode();
				} catch (Exception e) {
					return null;
				}
				if (code == null) return null;
				Matcher m = vp.matcher(code);
				if (m.find()) {
					return m.group(1);
				}
				// Try generic version constant
				Matcher vm = Pattern.compile("VERSION(?:_NAME)?\\s*=\\s*=\"([^\"]+)\"").matcher(code);
				if (vm.find()) {
					return vm.group(1);
				}
				return null;
			}
		}
		return null;
	}


	@Override
	protected void applyArgs(Map<String, Object> args) {
		// No options.
	}

	@Override
	protected String getDaemonCommandName() {
		return "framework-detect";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		return new LinkedHashMap<>();
	}
}
