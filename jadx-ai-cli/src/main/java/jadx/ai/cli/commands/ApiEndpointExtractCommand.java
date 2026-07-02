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
import jadx.api.ResourceFile;
import jadx.api.ResourceType;

/**
 * Extracts API endpoints from decompiled code by scanning Retrofit HTTP annotations,
 * OkHttp3 usage, and URL string literals. Absorbs the API-extractor design from
 * {@code mobile-security-mcp}'s {@code api-extractor.ts} (which parses smali for
 * Retrofit annotations and OkHttp fields) and reimplements it natively over jadx's
 * parsed Java model — producing structured endpoint data without any external tooling.
 *
 * <p>Besides the structured Retrofit/OkHttp/Volley extractors, a generic {@link #URL_LITERAL}
 * fallback harvests any {@code http(s)://...} literal in code (including URLs assembled via
 * {@code String.format("%s/api", "https://...")}, where the URL survives as a format argument
 * and the {@code .url("...")}-anchored arms miss it), and resources (strings.xml/ARSC) are
 * scanned for URLs stored outside code ({@code getString(R.string.base_url)}). Both close
 * silent-FN gaps where the URL never appears as a direct {@code .url("...")} argument.
 */
@Command(name = "api-endpoint-extract", description = "Extract API endpoints from Retrofit annotations, OkHttp usage, URL literals, and string resources")
public class ApiEndpointExtractCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum endpoints to return", defaultValue = "200")
	protected int limit = 200;

	@Option(names = { "--no-resources" }, description = "Skip strings.xml/ARSC resources (scan code only)")
	protected boolean noResources;

	/** Retrofit HTTP annotation patterns. */
	private static final Pattern RETROFIT_GET = Pattern.compile("@GET\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern RETROFIT_POST = Pattern.compile("@POST\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern RETROFIT_PUT = Pattern.compile("@PUT\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern RETROFIT_DELETE = Pattern.compile("@DELETE\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern RETROFIT_PATCH = Pattern.compile("@PATCH\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern RETROFIT_HTTP = Pattern.compile("@HTTP\\s*\\(.*?method\\s*=\\s*\"(\\w+)\".*?path\\s*=\\s*\"([^\"]+)\"", Pattern.DOTALL);
	/**
	 * Retrofit dynamic-URL endpoint: a method annotated {@code @Url} takes the full URL/path as a
	 * runtime argument, so NO literal path appears in code — the {@code @GET("...")}-style extractors
	 * all miss it. Previously DECLARED but never wired into execute (a dead field = silent FN); now
	 * scanned to flag these dynamic-URL endpoints. Package-private for testing.
	 */
	static final Pattern RETROFIT_URL = Pattern.compile("@Url\\b");
	private static final Pattern RETROFIT_BASE_URL = Pattern.compile("Retrofit\\.Builder\\(\\).*?baseUrl\\s*\\(\"([^\"]+)\"\\)");

	/** OkHttp / Volley patterns. */
	private static final Pattern OKHTTP_URL = Pattern.compile("\\.url\\s*\\(\"([^\"]+)\"\\)");
	private static final Pattern VOLLEY_URL = Pattern.compile("JsonObjectRequest\\s*\\(\\s*\\d+\\s*,\\s*\"([^\"]+)\"");

	/**
	 * Generic URL fallback. Harvests any {@code http(s)://...} literal in code, regardless of whether
	 * it appears inside a {@code .url("...")} call — this catches URLs assembled via
	 * {@code String.format("%s/api", "https://host")} (the URL survives as a format argument the
	 * {@code .url(}-anchored arms miss) and URLs assigned to a field then passed indirectly. Package-private
	 * for testing.
	 */
	static final Pattern URL_LITERAL = Pattern.compile("https?://[\\w./\\-?&=%+#:{}]+");

	/** Base URL from Retrofit.Builder or static field. */
	private static final Pattern BASE_URL_FIELD = Pattern.compile("(?:static\\s+)?(?:final\\s+)?String\\s+BASE_URL\\s*=\\s*\"(https?://[^\"]+)\"", Pattern.CASE_INSENSITIVE);

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
		Object nr = args.get("noResources");
		if (nr != null) {
			this.noResources = Boolean.TRUE.equals(nr) || "true".equals(nr.toString());
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

			// Retrofit @Url — dynamic-URL endpoint: the full URL/path is a runtime argument, so no
			// literal path appears in code (the @GET("...")-style extractors all miss it). Flag the
			// method as a dynamic-URL endpoint. ONE per @Url occurrence (each marks a distinct method).
			Matcher urlAnnotM = RETROFIT_URL.matcher(code);
			while (urlAnnotM.find() && endpoints.size() < limit) {
				Map<String, Object> ep = new LinkedHashMap<>();
				ep.put("method", "DYNAMIC");
				ep.put("path", "<runtime @Url argument>");
				ep.put("source", "retrofit-@Url");
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

			// Generic URL-literal fallback: harvest any http(s):// literal not already caught by the
			// structured arms — notably URLs assembled via String.format("%s/api", "https://host") (the
			// URL survives as a format argument) and URLs passed indirectly via a field. Dedup handles
			// overlaps with the okhttp/volley arms above.
			if (endpoints.size() < limit) {
				Matcher urlM = URL_LITERAL.matcher(code);
				while (urlM.find() && endpoints.size() < limit) {
					Map<String, Object> ep = new LinkedHashMap<>();
					ep.put("method", "UNKNOWN");
					ep.put("url", urlM.group());
					ep.put("source", "url-literal");
					ep.put("className", fullName);
					endpoints.add(ep);
				}
			}
		}

		// Resource scan: URLs stored in strings.xml/ARSC (loaded via getString(R.string.x)) never appear
		// in code as a literal, so the code-only arms above miss them entirely — a silent FN for apps that
		// externalize their base URL. Mirrors FirebaseScanCommand/SecretsScanCommand's resource path.
		if (!noResources) {
			for (ResourceFile res : decompiler.getResources()) {
				if (endpoints.size() >= limit) {
					break;
				}
				ResourceType type = res.getType();
				if (type != ResourceType.XML && type != ResourceType.ARSC && type != ResourceType.MANIFEST) {
					continue;
				}
				try {
					var container = res.loadContent();
					if (container == null) {
						continue;
					}
					var codeInfo = container.getText();
					if (codeInfo == null) {
						continue;
					}
					String text = codeInfo.toString();
					Matcher resM = URL_LITERAL.matcher(text);
					while (resM.find() && endpoints.size() < limit) {
						Map<String, Object> ep = new LinkedHashMap<>();
						ep.put("method", "UNKNOWN");
						ep.put("url", resM.group());
						ep.put("source", "resource");
						ep.put("className", res.getOriginalName());
						endpoints.add(ep);
					}
				} catch (Exception ignored) {
					// skip unreadable resources
				}
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
		if (noResources) {
			args.put("noResources", true);
		}
		return args;
	}
}
