package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.ManifestUtil;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Deep-link / app-link attack-surface inventory — MASVS MSTG-PLATFORM.
 * Native: reads jadx's parsed model and decoded manifest, no external tool.
 *
 * <p>Distinct from {@code intent-scan} (generic Intent vulnerabilities — mutable PendingIntent,
 * sticky broadcasts) and {@code intent-redirection-scan} (nested-Intent forwarding / confused-deputy).
 * This command inventories the <b>deep-link attack surface</b> itself: which URI schemes, hosts,
 * and paths the app declares it will handle, and which components are exposed through them.
 * A deep-link inventory is the first step in every mobile pentest — it tells you what to fuzz.
 *
 * <p>Scans both the manifest (static intent-filter declarations) and code (dynamic deep-link
 * handling via {@code Intent.parseUri()}, {@code ACTION_VIEW}, {@code Uri.parse()} in
 * Activity/Service/BroadcastReceiver).
 *
 * <p>Manifest findings: each {@code <intent-filter>} with a {@code <data>} element produces a
 * finding with scheme/host/pathPrefix/pathPattern/pathSuffix, plus the component name and whether
 * it is exported. Code findings: classes that dynamically construct or parse deep-link URIs.
 *
 * <p>Inventory shape (no severity — a deep link is a surface, not a vulnerability per se;
 * the risk depends on what the target component does with the input).
 *
 * Returns {@code {findings:[{category,source,lineNumber,scheme,host,path,component,exported,detail}],
 * count, schemes, hosts, exportedDeepLinks, hasDeepLinks, truncated}}.
 */
@Command(name = "deeplink-scan",
		description = "Inventory deep-link / app-link attack surface (MASVS MSTG-PLATFORM): manifest <intent-filter> <data> declarations (scheme/host/path) + dynamic deep-link handling in code (Intent.parseUri / ACTION_VIEW / Uri.parse). Distinct from intent-scan and intent-redirection-scan; answers what-to-fuzz for a mobile pentest")
public class DeeplinkScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	// --- Manifest patterns ---

	/** Self-closing <activity ... /> or <activity-alias ... /> */
	private static final Pattern SELF_CLOSING_ACTIVITY = Pattern.compile(
			"<(activity|activity-alias)\\b([^>]*?)/>", Pattern.DOTALL);
	/** Block <activity ...>...</activity> */
	private static final Pattern BLOCK_ACTIVITY = Pattern.compile(
			"<(activity|activity-alias)\\b([^>]*?)>(.*?)</\\1>", Pattern.DOTALL);
	/** <service ... /> */
	private static final Pattern SELF_CLOSING_SERVICE = Pattern.compile(
			"<service\\b([^>]*?)/>", Pattern.DOTALL);
	/** <service ...>...</service> */
	private static final Pattern BLOCK_SERVICE = Pattern.compile(
			"<service\\b([^>]*?)>(.*?)</service>", Pattern.DOTALL);
	/** Extract android:name from tag attributes. */
	private static final Pattern ATTR_NAME = Pattern.compile(
			Pattern.quote("android:name") + "\\s*=\\s*\"([^\"]+)\"");
	/** Extract android:exported from tag attributes. */
	private static final Pattern ATTR_EXPORTED = Pattern.compile(
			Pattern.quote("android:exported") + "\\s*=\\s*\"(true|false)\"");
	/** <intent-filter>...</intent-filter> block. */
	private static final Pattern INTENT_FILTER = Pattern.compile(
			"<intent-filter>(.*?)</intent-filter>", Pattern.DOTALL);
	/** <data ... /> element within intent-filter. */
	private static final Pattern DATA_ELEMENT = Pattern.compile(
			"<data\\b([^>]*?)/?>", Pattern.DOTALL);
	/** Data attributes. */
	private static final Pattern ATTR_SCHEME = Pattern.compile(
			Pattern.quote("android:scheme") + "\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern ATTR_HOST = Pattern.compile(
			Pattern.quote("android:host") + "\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern ATTR_PATH_PREFIX = Pattern.compile(
			Pattern.quote("android:pathPrefix") + "\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern ATTR_PATH_PATTERN = Pattern.compile(
			Pattern.quote("android:pathPattern") + "\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern ATTR_PATH = Pattern.compile(
			Pattern.quote("android:path") + "\\s*=\\s*\"([^\"]+)\"");
	/** <action android:name="android.intent.action.VIEW" /> — deep-link action. */
	private static final Pattern ACTION_VIEW = Pattern.compile(
			"android\\.intent\\.action\\.VIEW");

	// --- Code patterns ---

	private static final Pattern DEEPLINK_MARKER = Pattern.compile(
			"Intent\\.parseUri|ACTION_VIEW|Intent\\.ACTION_VIEW|deeplink|deep_link|deepLink");
	private static final Pattern INTENT_PARSE_URI = Pattern.compile("Intent\\.parseUri\\s*\\(");
	private static final Pattern CODE_ACTION_VIEW = Pattern.compile("ACTION_VIEW|Intent\\.ACTION_VIEW");
	private static final Pattern URI_PARSE = Pattern.compile("Uri\\.parse\\s*\\(");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();
		TreeSet<String> schemes = new TreeSet<>();
		TreeSet<String> hosts = new TreeSet<>();
		int exportedDeepLinks = 0;
		boolean hasDeepLinks = false;

		// --- Manifest scan ---
		String manifest = ManifestUtil.loadManifestText(decompiler);
		if (manifest != null) {
			// Process activities and activity-aliases
			List<Matcher> activityMatchers = new ArrayList<>();
			activityMatchers.add(SELF_CLOSING_ACTIVITY.matcher(manifest));
			activityMatchers.add(BLOCK_ACTIVITY.matcher(manifest));
			for (Matcher am : activityMatchers) {
				while (am.find() && findings.size() < limit) {
					String tag = am.group(1) != null ? am.group(1) : "activity";
					String attrs = am.group(2);
					String body = am.groupCount() >= 3 ? am.group(3) : "";
					processComponent(manifest, attrs, body, tag, findings, schemes, hosts);
				}
			}
			// Process services
			Matcher sm1 = SELF_CLOSING_SERVICE.matcher(manifest);
			while (sm1.find() && findings.size() < limit) {
				String attrs = sm1.group(1);
				processComponent(manifest, attrs, "", "service", findings, schemes, hosts);
			}
			Matcher sm2 = BLOCK_SERVICE.matcher(manifest);
			while (sm2.find() && findings.size() < limit) {
				String attrs = sm2.group(1);
				String body = sm2.group(2);
				processComponent(manifest, attrs, body, "service", findings, schemes, hosts);
			}
		}

		// Count exported deep links
		for (Map<String, Object> f : findings) {
			if (Boolean.TRUE.equals(f.get("exported"))) {
				exportedDeepLinks++;
			}
		}
		hasDeepLinks = !findings.isEmpty();

		// --- Code scan ---
		for (JavaClass cls : decompiler.getClasses()) {
			if (findings.size() >= limit) {
				break;
			}
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
			if (code == null || code.isEmpty() || !DEEPLINK_MARKER.matcher(code).find()) {
				continue;
			}

			boolean reportedParseUri = false;
			boolean reportedActionView = false;
			boolean reportedUriParse = false;

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				if (!reportedParseUri && INTENT_PARSE_URI.matcher(line).find()) {
					hasDeepLinks = true;
					findings.add(codeFinding("dynamic_deeplink_parse", fullName, i + 1, null, null, null,
							"Intent.parseUri() dynamically constructs an Intent from a URI — deep-link handler; verify the URI source and target component validation"));
					reportedParseUri = true;
					continue;
				}

				if (!reportedActionView && CODE_ACTION_VIEW.matcher(line).find()) {
					hasDeepLinks = true;
					findings.add(codeFinding("action_view_handler", fullName, i + 1, null, null, null,
							"ACTION_VIEW Intent handling — the app processes incoming deep links; verify the target component validates the URI and does not redirect to non-exported components"));
					reportedActionView = true;
					continue;
				}

				if (!reportedUriParse && URI_PARSE.matcher(line).find()
						&& (line.contains("scheme") || line.contains("host") || line.contains("path"))) {
					hasDeepLinks = true;
					findings.add(codeFinding("uri_parse_deeplink", fullName, i + 1, null, null, null,
							"Uri.parse() with scheme/host/path inspection — deep-link routing logic; verify the parsed URI is validated before use"));
					reportedUriParse = true;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("schemes", new ArrayList<>(schemes));
		data.put("hosts", new ArrayList<>(hosts));
		data.put("exportedDeepLinks", exportedDeepLinks);
		data.put("hasDeepLinks", hasDeepLinks);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private void processComponent(String manifest, String attrs, String body, String componentType,
			List<Map<String, Object>> findings, TreeSet<String> schemes, TreeSet<String> hosts) {
		String componentName = attr(attrs, ATTR_NAME);
		if (componentName == null) {
			return;
		}
		// Determine exported: explicit attribute, or implicit (intent-filter present = exported by default pre-API-31)
		String exportedStr = attr(attrs, ATTR_EXPORTED);
		boolean hasIntentFilter = body.contains("<intent-filter>");
		boolean exported;
		if (exportedStr != null) {
			exported = "true".equals(exportedStr);
		} else {
			// Pre-API-31: intent-filter present → exported by default
			exported = hasIntentFilter;
		}

		// Find intent-filters with <data> elements
		Matcher ifm = INTENT_FILTER.matcher(body);
		while (ifm.find()) {
			String ifBody = ifm.group(1);
			// Only process intent-filters with ACTION_VIEW (deep-link filters)
			if (!ACTION_VIEW.matcher(ifBody).find()) {
				continue;
			}
			Matcher dm = DATA_ELEMENT.matcher(ifBody);
			while (dm.find() && findings.size() < limit) {
				String dataAttrs = dm.group(1);
				String scheme = attr(dataAttrs, ATTR_SCHEME);
				String host = attr(dataAttrs, ATTR_HOST);
				String pathPrefix = attr(dataAttrs, ATTR_PATH_PREFIX);
				String pathPattern = attr(dataAttrs, ATTR_PATH_PATTERN);
				String path = attr(dataAttrs, ATTR_PATH);
				String pathStr = path != null ? path : (pathPrefix != null ? pathPrefix : pathPattern);
				if (scheme != null) {
					schemes.add(scheme);
				}
				if (host != null) {
					hosts.add(host);
				}
				String uri = buildUri(scheme, host, pathStr);
				findings.add(manifestFinding("manifest_deeplink", componentName, componentType,
						scheme, host, pathStr, exported,
						"Deep link " + uri + " → " + componentName + " (" + componentType + ")"
								+ (exported ? " [EXPORTED]" : " [not exported]")));
			}
		}
	}

	private static String attr(String text, Pattern p) {
		Matcher m = p.matcher(text);
		return m.find() ? m.group(1) : null;
	}

	private static String buildUri(String scheme, String host, String path) {
		StringBuilder sb = new StringBuilder();
		if (scheme != null) {
			sb.append(scheme).append("://");
		}
		if (host != null) {
			sb.append(host);
		}
		if (path != null) {
			sb.append(path);
		}
		return sb.length() > 0 ? sb.toString() : "<data element>";
	}

	private static Map<String, Object> manifestFinding(String category, String component,
			String componentType, String scheme, String host, String path, boolean exported, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("category", category);
		f.put("source", "AndroidManifest.xml");
		f.put("lineNumber", 0);
		f.put("scheme", scheme);
		f.put("host", host);
		f.put("path", path);
		f.put("component", component);
		f.put("componentType", componentType);
		f.put("exported", exported);
		f.put("detail", detail);
		return f;
	}

	private static Map<String, Object> codeFinding(String category, String className, int line,
			String scheme, String host, String path, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("category", category);
		f.put("source", className);
		f.put("lineNumber", line);
		f.put("scheme", scheme);
		f.put("host", host);
		f.put("path", path);
		f.put("component", null);
		f.put("componentType", null);
		f.put("exported", null);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "deeplink-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
