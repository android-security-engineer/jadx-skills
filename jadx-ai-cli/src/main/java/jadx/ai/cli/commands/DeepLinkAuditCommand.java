package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.ManifestUtil;
import jadx.api.JadxDecompiler;

/**
 * Enumerates the app's deep-link / URI attack surface from {@code AndroidManifest.xml} — the
 * intent-filters that let external apps or the browser hand data to a component. Native capability:
 * parses jadx's decoded manifest, no external tool. For each {@code <intent-filter>} that declares
 * {@code android.intent.action.VIEW} it reconstructs the addressable URIs from the {@code <data>}
 * elements (scheme/host/port/path*) and flags risky shapes:
 * <ul>
 *   <li>{@code http}/{@code https} schemes with {@code BROWSABLE} — reachable straight from a web
 *       page (App-Link surface; auto-verify only if {@code android:autoVerify="true"})</li>
 *   <li>custom schemes with a wildcard/empty host — accept arbitrary deep-link data</li>
 * </ul>
 */
@Command(name = "deep-link-audit", description = "Enumerate deep-link / URI intent-filters (the externally-reachable attack surface)")
public class DeepLinkAuditCommand extends AbstractCommand {

	// One <intent-filter> ... </intent-filter> block (DOTALL, non-greedy).
	private static final Pattern FILTER = Pattern.compile("<intent-filter\\b([^>]*)>(.*?)</intent-filter>", Pattern.DOTALL);
	private static final Pattern DATA = Pattern.compile("<data\\b([^>]*?)/?>", Pattern.DOTALL);

	@Override
	protected void applyArgs(Map<String, Object> args) {
		// no options
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		String manifest = ManifestUtil.loadManifestText(decompiler);
		if (manifest == null) {
			return JsonOutput.error("ManifestNotFound", "AndroidManifest.xml not found in resources");
		}

		List<Map<String, Object>> deepLinks = new ArrayList<>();
		List<Map<String, Object>> findings = new ArrayList<>();

		Matcher fm = FILTER.matcher(manifest);
		while (fm.find()) {
			String filterAttrs = fm.group(1);
			String body = fm.group(2);
			if (!body.contains("android.intent.action.VIEW")) {
				continue; // VIEW is what makes a filter URI-addressable
			}
			boolean browsable = body.contains("android.intent.category.BROWSABLE");
			boolean autoVerify = "true".equalsIgnoreCase(attr(filterAttrs, "android:autoVerify"));

			List<String> schemes = new ArrayList<>();
			List<String> hosts = new ArrayList<>();
			List<String> paths = new ArrayList<>();
			Matcher dm = DATA.matcher(body);
			while (dm.find()) {
				String d = dm.group(1);
				addIfPresent(schemes, attr(d, "android:scheme"));
				addIfPresent(hosts, attr(d, "android:host"));
				addIfPresent(paths, attr(d, "android:path"));
				addIfPresent(paths, attr(d, "android:pathPrefix"));
				addIfPresent(paths, attr(d, "android:pathPattern"));
			}
			if (schemes.isEmpty()) {
				continue; // no data spec → not a deep link
			}

			Map<String, Object> link = new LinkedHashMap<>();
			link.put("schemes", schemes);
			link.put("hosts", hosts);
			link.put("paths", paths);
			link.put("browsable", browsable);
			link.put("autoVerify", autoVerify);
			link.put("exampleUris", buildExamples(schemes, hosts, paths));
			deepLinks.add(link);

			boolean web = schemes.contains("http") || schemes.contains("https");
			if (web && browsable && !autoVerify) {
				findings.add(finding("weblink_no_autoverify", "medium", schemes, hosts,
						"Browsable http(s) deep link without android:autoVerify — link hijacking is possible"));
			}
			boolean customWildcardHost = !web && (hosts.isEmpty() || hosts.contains("*"));
			if (customWildcardHost && browsable) {
				findings.add(finding("custom_scheme_open_host", "medium", schemes, hosts,
						"Browsable custom-scheme deep link with no/wildcard host — accepts arbitrary URIs"));
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("deepLinks", deepLinks);
		data.put("findings", findings);
		data.put("deepLinkCount", deepLinks.size());
		data.put("findingCount", findings.size());
		return JsonOutput.ok(data);
	}

	private static List<String> buildExamples(List<String> schemes, List<String> hosts, List<String> paths) {
		List<String> out = new ArrayList<>();
		for (String scheme : schemes) {
			if (hosts.isEmpty()) {
				out.add(scheme + "://");
			} else {
				for (String host : hosts) {
					String base = scheme + "://" + host;
					if (paths.isEmpty()) {
						out.add(base);
					} else {
						for (String p : paths) {
							out.add(base + (p.startsWith("/") ? p : "/" + p));
						}
					}
				}
			}
		}
		return out;
	}

	private static Map<String, Object> finding(String kind, String severity, List<String> schemes,
			List<String> hosts, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("schemes", schemes);
		f.put("hosts", hosts);
		f.put("detail", detail);
		return f;
	}

	private static void addIfPresent(List<String> list, String value) {
		if (value != null && !list.contains(value)) {
			list.add(value);
		}
	}

	private static String attr(String attrs, String name) {
		Matcher m = Pattern.compile(Pattern.quote(name) + "\\s*=\\s*\"([^\"]*)\"").matcher(attrs);
		return m.find() ? m.group(1) : null;
	}

	@Override
	protected String getDaemonCommandName() {
		return "deep-link-audit";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		return new java.util.HashMap<>();
	}
}
