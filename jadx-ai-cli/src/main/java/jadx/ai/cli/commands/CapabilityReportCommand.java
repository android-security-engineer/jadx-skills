package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Generates a high-level capability summary of the APK — what the app does at a glance.
 * Absorbs the {@code capability_report} design from {@code dex-analyzer-for-llm}'s tool
 * surface, which provides a bounded, LLM-friendly summary of top permissions, categories,
 * and the most-invoked APIs. This native implementation scans decompiled code for permission
 * usage, network endpoints, crypto APIs, dynamic loading, file I/O, and sensitive system API
 * calls, then produces a concise "what can this app do?" report.
 */
@Command(name = "capability-report", description = "Generate a high-level capability summary of the APK")
public class CapabilityReportCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--top" }, description = "Top N items per category", defaultValue = "20")
	protected int top = 20;

	/** A capability category with detection patterns. */
	private static final class CapCategory {
		final String name;
		final Pattern[] patterns;

		CapCategory(String name, Pattern[] patterns) {
			this.name = name;
			this.patterns = patterns;
		}
	}

	private static final Pattern PERM_API = Pattern.compile(
			"(?:LocationManager|TelephonyManager|CameraManager|SensorManager|AudioManager|"
					+ "WifiManager|BluetoothAdapter|AccountManager|KeyguardManager|"
					+ "ClipboardManager|ConnectivityManager|DownloadManager|NotificationManager|"
					+ "ActivityManager|PackageManager|AlarmManager|WindowManager)");
	private static final Pattern NETWORK_API = Pattern.compile(
			"(?:HttpURLConnection|OkHttpClient|Retrofit|Volley|URLConnection|"
					+ "WebView|AsyncTask|Socket\\b)");
	private static final Pattern CRYPTO_API = Pattern.compile(
			"(?:Cipher|MessageDigest|Signature|Mac|SecretKey|KeyGenerator|"
					+ "KeyPairGenerator|KeyStore|SecureRandom|AES|RSA|DES|ECB|CBC)");
	private static final Pattern DYNAMIC_LOADING = Pattern.compile(
			"(?:DexClassLoader|PathClassLoader|ClassLoader\\.loadClass|"
					+ "System\\.loadLibrary|Runtime\\.exec|ProcessBuilder|"
					+ "invoke\\(|Method\\.invoke|Proxy\\.newProxyInstance)");
	private static final Pattern FILE_IO = Pattern.compile(
			"(?:FileInputStream|FileOutputStream|FileReader|FileWriter|"
					+ "BufferedReader|BufferedWriter|SharedPreferences|"
					+ "openFileOutput|openFileInput|ContentResolver|SQLiteDatabase)");
	private static final Pattern SENSITIVE_API = Pattern.compile(
			"(?:getDeviceId|getSubscriberId|getSimSerialNumber|getCellLocation|"
					+ "getLastKnownLocation|requestLocationUpdates|"
					+ "takePicture|MediaRecorder|AudioRecord|"
					+ "READ_CONTACTS|READ_CALL_LOG|READ_SMS|SEND_SMS|"
					+ "getAccounts|setClipboard|getText\\(\\)|setText\\("
					+ "|registerContentObserver|query\\(Uri)");
	private static final Pattern AUTH_API = Pattern.compile(
			"(?:BiometricPrompt|FingerprintManager|KeyGenParameterSpec|"
					+ "AlertDialog|login|authenticate|signIn|signUp|"
					+ "GoogleSignIn|FacebookSdk|OAuth|token)");

	private static final List<CapCategory> CATEGORIES = List.of(
			new CapCategory("system_services", new Pattern[] { PERM_API }),
			new CapCategory("network", new Pattern[] { NETWORK_API }),
			new CapCategory("crypto", new Pattern[] { CRYPTO_API }),
			new CapCategory("dynamic_loading", new Pattern[] { DYNAMIC_LOADING }),
			new CapCategory("file_io", new Pattern[] { FILE_IO }),
			new CapCategory("sensitive_apis", new Pattern[] { SENSITIVE_API }),
			new CapCategory("authentication", new Pattern[] { AUTH_API }));

	// Permission→API mapping for top permission groups
	private static final Map<String, String[]> PERM_GROUPS = new LinkedHashMap<>();
	static {
		PERM_GROUPS.put("location", new String[] { "LocationManager", "getLastKnownLocation", "requestLocationUpdates", "FusedLocationProviderClient" });
		PERM_GROUPS.put("phone/device", new String[] { "TelephonyManager", "getDeviceId", "getSubscriberId", "getSimSerialNumber" });
		PERM_GROUPS.put("camera", new String[] { "CameraManager", "takePicture", "MediaRecorder" });
		PERM_GROUPS.put("audio/mic", new String[] { "AudioRecord", "MediaRecorder", "AudioManager" });
		PERM_GROUPS.put("storage", new String[] { "FileOutputStream", "openFileOutput", "SharedPreferences", "SQLiteDatabase" });
		PERM_GROUPS.put("network", new String[] { "HttpURLConnection", "OkHttpClient", "WebView", "ConnectivityManager" });
		PERM_GROUPS.put("contacts", new String[] { "READ_CONTACTS", "ContactsContract", "query(Uri" });
		PERM_GROUPS.put("sms", new String[] { "READ_SMS", "SEND_SMS", "SmsManager" });
		PERM_GROUPS.put("biometric", new String[] { "BiometricPrompt", "FingerprintManager" });
		PERM_GROUPS.put("accounts", new String[] { "AccountManager", "getAccounts" });
	}

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("top")) {
			this.top = ((Number) args.get("top")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		Map<String, Integer> categoryCounts = new LinkedHashMap<>();
		for (CapCategory cat : CATEGORIES) {
			categoryCounts.put(cat.name, 0);
		}

		Map<String, List<String>> categoryClasses = new LinkedHashMap<>();
		for (CapCategory cat : CATEGORIES) {
			categoryClasses.put(cat.name, new ArrayList<>());
		}

		// Track permission group usage
		Map<String, Integer> permGroupHits = new LinkedHashMap<>();
		for (String group : PERM_GROUPS.keySet()) {
			permGroupHits.put(group, 0);
		}

		int totalClasses = 0;

		for (JavaClass cls : decompiler.getClasses()) {
			String fullName = cls.getFullName();
			if (packageFilter != null && !fullName.startsWith(packageFilter)) {
				continue;
			}
			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty()) {
				continue;
			}
			totalClasses++;

			for (CapCategory cat : CATEGORIES) {
				for (Pattern p : cat.patterns) {
					if (p.matcher(code).find()) {
						int count = categoryCounts.get(cat.name) + 1;
						categoryCounts.put(cat.name, count);
						List<String> classes = categoryClasses.get(cat.name);
						if (classes.size() < top) {
							classes.add(fullName);
						}
						break;
					}
				}
			}

			// Check permission groups
			for (Map.Entry<String, String[]> entry : PERM_GROUPS.entrySet()) {
				for (String marker : entry.getValue()) {
					if (code.contains(marker)) {
						permGroupHits.put(entry.getKey(), permGroupHits.get(entry.getKey()) + 1);
						break;
					}
				}
			}
		}

		// Build top permission groups (sorted by hit count, descending)
		List<Map<String, Object>> topPermGroups = new ArrayList<>();
		permGroupHits.entrySet().stream()
				.filter(e -> e.getValue() > 0)
				.sorted((a, b) -> b.getValue().compareTo(a.getValue()))
				.limit(top)
				.forEach(e -> {
					Map<String, Object> pg = new LinkedHashMap<>();
					pg.put("group", e.getKey());
					pg.put("classCount", e.getValue());
					topPermGroups.add(pg);
				});

		// Build summary
		List<String> summary = new ArrayList<>();
		if (categoryCounts.get("network") > 0) {
			summary.add("Network access (" + categoryCounts.get("network") + " classes)");
		}
		if (categoryCounts.get("crypto") > 0) {
			summary.add("Cryptography (" + categoryCounts.get("crypto") + " classes)");
		}
		if (categoryCounts.get("sensitive_apis") > 0) {
			summary.add("Sensitive APIs (" + categoryCounts.get("sensitive_apis") + " classes)");
		}
		if (categoryCounts.get("dynamic_loading") > 0) {
			summary.add("Dynamic code loading (" + categoryCounts.get("dynamic_loading") + " classes)");
		}
		if (categoryCounts.get("file_io") > 0) {
			summary.add("File I/O (" + categoryCounts.get("file_io") + " classes)");
		}
		if (categoryCounts.get("authentication") > 0) {
			summary.add("Authentication (" + categoryCounts.get("authentication") + " classes)");
		}

		Map<String, Object> capabilities = new LinkedHashMap<>();
		capabilities.put("totalClasses", totalClasses);
		for (CapCategory cat : CATEGORIES) {
			capabilities.put(cat.name, categoryCounts.get(cat.name));
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("capabilities", capabilities);
		data.put("topPermissionGroups", topPermGroups);
		data.put("sampleClasses", categoryClasses);
		data.put("summary", summary);
		return JsonOutput.ok(data);
	}

	@Override
	protected String getDaemonCommandName() {
		return "capability-report";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("top", top);
		return args;
	}
}
