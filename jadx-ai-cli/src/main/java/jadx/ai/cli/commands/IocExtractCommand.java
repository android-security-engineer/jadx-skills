package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Extracts indicators of compromise (URLs, IP addresses, domains, REST endpoints) from
 * decompiled code. Endpoints are surfaced by matching common HTTP-client markers (Retrofit
 * annotations, OkHttp builders). Native capability — reads jadx's parsed model, no external tool.
 */
@Command(name = "ioc-extract", description = "Extract URLs, IPs, domains and REST endpoints from code")
public class IocExtractCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--types" }, description = "Comma-separated IOC types: url,ip,domain,endpoint", defaultValue = "url,ip,domain,endpoint")
	protected String types = "url,ip,domain,endpoint";

	@Option(names = { "--defang" }, description = "Defang indicators (http->hxxp, . -> [.])")
	protected boolean defang;

	@Option(names = { "--decode-defang" }, description = "Also decode already-defanged indicators (hxxp->http, [.]->., [at]->@)")
	protected boolean decodeDefang;

	@Option(names = { "--limit" }, description = "Maximum indicators per category", defaultValue = "500")
	protected int limit = 500;

	private static final Pattern URL = Pattern.compile("\\b(?:https?|ftp|ws|wss)://[\\w.\\-]+(?::\\d+)?(?:/[\\w.\\-/%?#&=+~@!$',;:()*]*)?");
	private static final Pattern IP = Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b");
	private static final Pattern DOMAIN = Pattern.compile("\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+(?:com|net|org|io|co|info|biz|gov|edu|cn|ru|uk|de|app|dev|xyz|top|site|online|tk|cc|me|tv|api|cloud)\\b");
	private static final Pattern ENDPOINT_ANNO = Pattern.compile("@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP)\\s*\\(\\s*\"([^\"]+)\"");
	private static final Pattern ENDPOINT_OKHTTP = Pattern.compile("\\.url\\s*\\(\\s*\"([^\"]+)\"");

	// Filter out framework/library noise that looks like a domain but isn't an IOC.
	private static final Set<String> DOMAIN_NOISE = Set.of(
			"android.app", "java.io", "java.lang", "java.net", "java.util",
			"javax.net", "kotlin.io", "kotlinx.coroutines", "androidx.core");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.get("types") != null) {
			this.types = (String) args.get("types");
		}
		if (args.containsKey("defang")) {
			this.defang = Boolean.TRUE.equals(args.get("defang"));
		}
		if (args.containsKey("decode-defang")) {
			this.decodeDefang = Boolean.TRUE.equals(args.get("decode-defang"));
		}
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		Set<String> want = new LinkedHashSet<>();
		for (String t : types.split(",")) {
			want.add(t.trim().toLowerCase());
		}

		Set<String> urls = new LinkedHashSet<>();
		Set<String> ips = new LinkedHashSet<>();
		Set<String> domains = new LinkedHashSet<>();
		List<Map<String, Object>> endpoints = new ArrayList<>();

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

			// Scan the raw code, plus a defang-decoded copy if requested. Malware/authors
			// routinely paste indicators in defanged form (hxxp://, [.], [at]) into comments
			// or strings; decoding recovers them so they're extracted alongside real ones.
			List<String> sources = new ArrayList<>();
			sources.add(code);
			String decoded = null;
			if (decodeDefang) {
				decoded = decodeDefang(code);
				if (!decoded.equals(code)) {
					sources.add(decoded);
				}
			}

			for (String src : sources) {
				if (want.contains("url")) {
					collect(URL, src, 0, urls);
				}
				if (want.contains("ip")) {
					collect(IP, src, 0, ips);
				}
				if (want.contains("domain")) {
					collectDomains(src, domains);
				}
				if (want.contains("endpoint")) {
					collectEndpoints(cls.getName(), src, endpoints);
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		// Silent-truncation signal (MULTI_LIST): urls/ips/domains (Sets) are each capped at `limit`
		// inside collect(); endpoints is capped both inside collectEndpoints AND by a subList(0, limit)
		// here — a SECOND truncation point on the same list. Each collection's size maxes at `limit`
		// when truncated, so `size >= limit` is the conservative signal (can't distinguish "exactly
		// limit" from "truncated to limit" — safe side: report truncated, the AI re-runs to be sure).
		boolean truncated = urls.size() >= limit || ips.size() >= limit
				|| domains.size() >= limit || endpoints.size() >= limit;
		if (want.contains("url")) {
			data.put("urls", finalize(urls));
		}
		if (want.contains("ip")) {
			data.put("ips", finalize(ips));
		}
		if (want.contains("domain")) {
			data.put("domains", finalize(domains));
		}
		if (want.contains("endpoint")) {
			data.put("endpoints", endpoints.size() > limit ? endpoints.subList(0, limit) : endpoints);
		}
		data.put("truncated", truncated);
		return JsonOutput.ok(data);
	}

	private void collect(Pattern p, String text, int group, Set<String> out) {
		Matcher m = p.matcher(text);
		while (m.find() && out.size() < limit) {
			out.add(m.group(group));
		}
	}

	private void collectDomains(String text, Set<String> out) {
		Matcher m = DOMAIN.matcher(text);
		while (m.find() && out.size() < limit) {
			String d = m.group(0);
			boolean noise = false;
			for (String n : DOMAIN_NOISE) {
				if (d.startsWith(n)) {
					noise = true;
					break;
				}
			}
			if (!noise) {
				out.add(d);
			}
		}
	}

	private void collectEndpoints(String className, String text, List<Map<String, Object>> out) {
		Matcher anno = ENDPOINT_ANNO.matcher(text);
		while (anno.find() && out.size() < limit) {
			out.add(endpoint(className, anno.group(2), "@" + anno.group(1)));
		}
		Matcher ok = ENDPOINT_OKHTTP.matcher(text);
		while (ok.find() && out.size() < limit) {
			out.add(endpoint(className, ok.group(1), ".url()"));
		}
	}

	private Map<String, Object> endpoint(String className, String value, String annotation) {
		Map<String, Object> e = new LinkedHashMap<>();
		e.put("className", className);
		e.put("value", defang ? defang(value) : value);
		e.put("annotation", annotation);
		return e;
	}

	private List<String> finalize(Set<String> values) {
		List<String> out = new ArrayList<>(values.size());
		for (String v : values) {
			out.add(defang ? defang(v) : v);
		}
		return out;
	}

	/** Render an indicator safe to paste into reports/chat. */
	static String defang(String s) {
		if (s == null) {
			return null;
		}
		return s.replace("http", "hxxp").replace(".", "[.]");
	}

	/**
	 * Reverse of {@link #defang}: restore the real indicator behind common defang notations —
	 * {@code hxxp(s)://}, {@code [.]}, {@code [dot]}, {@code [at]}, {@code hxxp}. Absorbed
	 * from {@code dex-analyzer-for-llm}'s defang-aware IOC extraction.
	 */
	static String decodeDefang(String s) {
		if (s == null) {
			return null;
		}
		return s
				.replace("hxxps", "https")
				.replace("hxxp", "http")
				.replace("[.]", ".")
				.replace("[dot]", ".")
				.replace("[at]", "@")
				.replace("[:]", ":");
	}

	@Override
	protected String getDaemonCommandName() {
		return "ioc-extract";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("types", types);
		args.put("defang", defang);
		args.put("decode-defang", decodeDefang);
		args.put("limit", limit);
		return args;
	}
}
