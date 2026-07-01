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
 * Extracts API endpoints from decompiled code by scanning Retrofit HTTP annotations,
 * OkHttp3 usage, and URL string literals. Absorbs the API-extractor design from
 * {@code mobile-security-mcp}'s {@code api-extractor.ts} (which parses smali for
 * Retrofit annotations and OkHttp fields) and reimplements it natively over jadx's
 * parsed Java model — producing structured endpoint data without any external tooling.
 */
@Command(name = "api-endpoint-extract", description = "Extract API endpoints from Retrofit annotations, OkHttp usage, and URL literals")
public class ApiEndpointExtractCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum endpoints to return", defaultValue = "200")
	protected int limit = 200;

	/** Retrofit HTTP annotation patterns. */
	private static final Pattern RETROFIT_GET = Pattern.compile("@GET\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern RETROFIT_POST = Pattern.compile("@POST\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern RETROFIT_PUT = Pattern.compile("@PUT\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern RETROFIT_DELETE = Pattern.compile("@DELETE\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern RETROFIT_PATCH = Pattern.compile("@PATCH\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern RETROFIT_HTTP = Pattern.compile("@HTTP\\s*\\(.*?method\\s*=\\s*\"(\\w+)\".*?path\\s*=\\s*\"([^\"]+)\"", Pattern.DOTALL);
	private static final Pattern RETROFIT_URL = Pattern.compile("@Url\\b");
	private static final Pattern RETROFIT_BASE_URL = Pattern.compile("Retrofit\\.Builder\\(\\).*?baseUrl\\s*\\(\"([^\"]+)\"\\)");

	/** OkHttp / Volley patterns. */
	private static final Pattern OKHTTP_URL = Pattern.compile("\\.url\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern OKHTTP_BUILDER = Pattern.compile("Request\\.Builder\\(\\)");
	private static final Pattern VOLLEY_URL = Pattern.compile("JsonObjectRequest\\s*\\(\\s*\\d+\\s*,\\s*\"([^\"]+)\"");

	/** Generic URL pattern. */
	private static final Pattern URL_LITERAL = Pattern.compile("https?://[\\w./\\-?&=%+#:{}]+");

	/** Base URL from Retrofit.Builder or static field. */
	private static final Pattern BASE_URL_FIELD = Pattern.compile("(?:static\\s+)?(?:final\\s+)?String\\s+BASE_URL\\s*=\\s*\"(https?://[^\"]+)\"", Pattern.CASE_INSENSITIVE);

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> endpoints = new ArrayList<>();
		String detectedBaseUrl = null;

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

			// Detect base URL
			if (detectedBaseUrl == null) {
				Matcher bm = RETROFIT_BASE_URL.matcher(code);
				if (bm.find()) {
					detectedBaseUrl = bm.group(1);
				} else {
					Matcher bfm = BASE_URL_FIELD.matcher(code);
					if (bfm.find()) {
						detectedBaseUrl = bfm.group(1);
					}
				}
			}

			// Retrofit @GET
			scanAnnotation(code, "GET", RETROFIT_GET, fullName, endpoints);
			// Retrofit @POST
			scanAnnotation(code, "POST", RETROFIT_POST, fullName, endpoints);
			// Retrofit @PUT
			scanAnnotation(code, "PUT", RETROFIT_PUT, fullName, endpoints);
			// Retrofit @DELETE
			scanAnnotation(code, "DELETE", RETROFIT_DELETE, fullName, endpoints);
			// Retrofit @PATCH
			scanAnnotation(code, "PATCH", RETROFIT_PATCH, fullName, endpoints);
			// Retrofit @HTTP(method, path)
			Matcher httpM = RETROFIT_HTTP.matcher(code);
			while (httpM.find() && endpoints.size() < limit) {
				Map<String, Object> ep = new LinkedHashMap<>();
				ep.put("method", httpM.group(1));
				ep.put("path", httpM.group(2));
				ep.put("source", "retrofit-@HTTP");
				ep.put("className", fullName);
				endpoints.add(ep);
			}

			// OkHttp .url()
			Matcher okhttpM = OKHTTP_URL.matcher(code);
			while (okhttpM.find() && endpoints.size() < limit) {
				String url = okhttpM.group(1);
				if (url.startsWith("http")) {
					Map<String, Object> ep = new LinkedHashMap<>();
					ep.put("method", "UNKNOWN");
					ep.put("url", url);
					ep.put("source", "okhttp-url");
					ep.put("className", fullName);
					endpoints.add(ep);
				}
			}

			// Volley URL
			Matcher volleyM = VOLLEY_URL.matcher(code);
			while (volleyM.find() && endpoints.size() < limit) {
				Map<String, Object> ep = new LinkedHashMap<>();
				ep.put("method", "UNKNOWN");
				ep.put("url", volleyM.group(1));
				ep.put("source", "volley");
				ep.put("className", fullName);
				endpoints.add(ep);
			}
		}

		// Second pass: resolve relative paths with detected base URL
		if (detectedBaseUrl != null) {
			for (Map<String, Object> ep : endpoints) {
				if (ep.containsKey("path") && !ep.containsKey("url")) {
					String path = (String) ep.get("path");
					if (path != null && !path.startsWith("http")) {
						String base = detectedBaseUrl;
						if (!base.endsWith("/") && !path.startsWith("/")) {
							path = "/" + path;
						} else if (base.endsWith("/") && path.startsWith("/")) {
							path = path.substring(1);
						}
						ep.put("url", base + path);
					} else if (path != null && path.startsWith("http")) {
						ep.put("url", path);
					}
				}
			}
		}

		// Deduplicate by url+method
		Map<String, Map<String, Object>> deduped = new LinkedHashMap<>();
		for (Map<String, Object> ep : endpoints) {
			String key = ep.getOrDefault("method", "") + ":" + ep.getOrDefault("url", ep.getOrDefault("path", ""));
			if (!deduped.containsKey(key)) {
				deduped.put(key, ep);
			}
		}
		List<Map<String, Object>> unique = new ArrayList<>(deduped.values());

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("endpoints", unique);
		data.put("endpointCount", unique.size());
		data.put("baseUrl", detectedBaseUrl);
		data.put("truncated", unique.size() >= limit);
		return JsonOutput.ok(data);
	}

	private void scanAnnotation(String code, String method, Pattern pattern, String className, List<Map<String, Object>> endpoints) {
		Matcher m = pattern.matcher(code);
		while (m.find() && endpoints.size() < limit) {
			Map<String, Object> ep = new LinkedHashMap<>();
			ep.put("method", method);
			ep.put("path", m.group(1));
			ep.put("source", "retrofit-@" + method);
			ep.put("className", className);
			endpoints.add(ep);
		}
	}

	@Override
	protected String getDaemonCommandName() {
		return "api-endpoint-extract";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
