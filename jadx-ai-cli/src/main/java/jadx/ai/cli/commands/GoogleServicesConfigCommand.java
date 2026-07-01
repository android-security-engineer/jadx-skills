package jadx.ai.cli.commands;

import java.io.BufferedReader;
import java.io.StringReader;
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
import jadx.api.ResourceFile;

/**
 * Extracts Google/Firebase service configuration from the APK. Parses
 * {@code google-services.json} from assets, scans resource strings for Google
 * config keys (google_app_id, google_api_key, etc.), and detects Firebase
 * URLs, storage buckets, and OAuth client IDs in decompiled code.
 * Absorbs the google-services extractor design from
 * {@code mobile-security-mcp}'s {@code google-services.ts}.
 */
@Command(name = "google-services-config", description = "Extract Google/Firebase service configuration from the APK")
public class GoogleServicesConfigCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum findings", defaultValue = "100")
	protected int limit = 100;

	/** Google config keys to look for in string resources. */
	private static final String[] GOOGLE_STRING_KEYS = {
		"google_app_id", "google_api_key", "google_crash_reporting_api_key",
		"google_storage_bucket", "project_id", "gcm_defaultSenderId",
		"default_web_client_id", "firebase_database_url", "google_maps_key",
		"google_maps_api_key", "google_app_id", "android_client_id",
		"web_client_id", "firebase_url"
	};

	/** Patterns for detecting Google/Firebase config in code. */
	private static final Pattern GOOGLE_API_KEY = Pattern.compile("AIza[0-9A-Za-z_-]{35}");
	private static final Pattern FIREBASE_URL = Pattern.compile("https?://[\\w.-]+\\.firebaseio\\.com");
	private static final Pattern FIREBASE_STORAGE = Pattern.compile("gs://[\\w.-]+\\.appspot\\.com");
	private static final Pattern PROJECT_ID_PATTERN = Pattern.compile("project[_-]?id\\s*[=:]\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
	private static final Pattern STORAGE_BUCKET = Pattern.compile("(?:storage[_-]?bucket|bucket)\\s*[=:]\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
	private static final Pattern OAUTH_CLIENT_ID = Pattern.compile("[0-9]+-[a-z0-9]+\\.apps\\.googleusercontent\\.com");
	private static final Pattern GOOGLE_SERVICES_JSON_KEY = Pattern.compile("\"(project_id|project_number|firebase_url|storage_bucket|mobilesdk_app_id|current_key|client_id|package_name)\"\\s*:\\s*\"([^\"]+)\"");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();
		Map<String, Object> googleServicesJson = null;
		Map<String, String> stringResources = new LinkedHashMap<>();

		// 1. Scan resources for google-services.json
		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name == null) continue;
			String normName = name.replace('\\', '/');
			if (normName.endsWith("google-services.json")) {
				try {
					String content = res.loadContent().getText().toString();
					googleServicesJson = parseGoogleServicesJson(content);
				} catch (Exception e) {
					// Skip unparseable
				}
			}
			// Scan string resources for Google config keys
			if (normName.contains("strings.xml") || normName.endsWith(".xml")) {
				try {
					String content = res.loadContent().getText().toString();
					if (content != null) {
						scanStringResources(content, stringResources);
					}
				} catch (Exception e) {
					// Skip
				}
			}
		}

		// 2. Scan decompiled code for Google/Firebase config
		List<Map<String, Object>> codeFindings = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			if (codeFindings.size() >= limit) break;
			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty()) continue;

			scanPattern(code, "google_api_key", GOOGLE_API_KEY, cls.getFullName(), codeFindings);
			scanPattern(code, "firebase_url", FIREBASE_URL, cls.getFullName(), codeFindings);
			scanPattern(code, "firebase_storage", FIREBASE_STORAGE, cls.getFullName(), codeFindings);
			scanPattern(code, "oauth_client_id", OAUTH_CLIENT_ID, cls.getFullName(), codeFindings);

			Matcher pm = PROJECT_ID_PATTERN.matcher(code);
			while (pm.find() && codeFindings.size() < limit) {
				Map<String, Object> f = new LinkedHashMap<>();
				f.put("kind", "project_id");
				f.put("value", pm.group(1));
				f.put("className", cls.getFullName());
				codeFindings.add(f);
			}
			Matcher sm = STORAGE_BUCKET.matcher(code);
			while (sm.find() && codeFindings.size() < limit) {
				Map<String, Object> f = new LinkedHashMap<>();
				f.put("kind", "storage_bucket");
				f.put("value", sm.group(1));
				f.put("className", cls.getFullName());
				codeFindings.add(f);
			}
		}

		// Build result
		Map<String, Object> data = new LinkedHashMap<>();
		data.put("googleServicesJson", googleServicesJson);
		data.put("stringResources", stringResources);
		data.put("codeFindings", codeFindings);
		data.put("totalFindings", codeFindings.size());
		return JsonOutput.ok(data);
	}

	private Map<String, Object> parseGoogleServicesJson(String content) {
		Map<String, Object> result = new LinkedHashMap<>();
		try {
			// Simple regex-based JSON extraction (no external JSON parser needed beyond Gson)
			Matcher m = GOOGLE_SERVICES_JSON_KEY.matcher(content);
			Map<String, String> topLevels = new LinkedHashMap<>();
			while (m.find()) {
				topLevels.put(m.group(1), m.group(2));
			}
			if (!topLevels.isEmpty()) {
				result.put("found", true);
				result.putAll(topLevels);
				// Extract package names
				List<String> packages = new ArrayList<>();
				Matcher pkgM = Pattern.compile("\"package_name\"\\s*:\\s*\"([^\"]+)\"").matcher(content);
				while (pkgM.find()) {
					packages.add(pkgM.group(1));
				}
				if (!packages.isEmpty()) {
					result.put("packages", packages);
				}
			}
		} catch (Exception e) {
			result.put("found", true);
			result.put("parseError", e.getMessage());
		}
		return result.isEmpty() ? null : result;
	}

	private void scanStringResources(String xml, Map<String, String> results) {
		for (String key : GOOGLE_STRING_KEYS) {
			Pattern p = Pattern.compile("name\\s*=\\s*[\"']" + Pattern.quote(key) + "[\"'][^>]*>([^<]+)<");
			Matcher m = p.matcher(xml);
			if (m.find()) {
				String value = m.group(1).trim();
				if (!value.isEmpty() && !results.containsKey(key)) {
					results.put(key, value);
				}
			}
		}
	}

	private void scanPattern(String code, String kind, Pattern pattern, String className, List<Map<String, Object>> findings) {
		Matcher m = pattern.matcher(code);
		while (m.find() && findings.size() < limit) {
			Map<String, Object> f = new LinkedHashMap<>();
			f.put("kind", kind);
			f.put("value", m.group());
			f.put("className", className);
			findings.add(f);
		}
	}

	@Override
	protected String getDaemonCommandName() {
		return "google-services-config";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("limit", limit);
		return args;
	}
}
