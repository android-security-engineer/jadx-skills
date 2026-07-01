package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
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
import jadx.api.JavaMethod;

/**
 * Locates every call site of a given API method — across the whole APK, not just one class's
 * methods. {@code usage --method} answers "who calls <em>this</em> method (in class X)?" via
 * jadx's cross-reference graph; it needs a concrete loaded {@link JavaMethod} and cannot find
 * calls to <em>external</em> framework APIs (e.g. {@code getDeviceId()}, {@code
 * loadLibrary}) that aren't APK classes. {@code dangerous-api-map} covers only the
 * permission-protected slice. This command fills the gap: it walks each method's decompiled
 * code and reports every {@code apiName(} invocation — caller class, caller method, line —
 * for any API name. Absorbed from {@code dex-analyzer-for-llm}'s {@code
 * find_call_sites_to_api} (DexKit call-site index) — same query, native.
 *
 * <p>Returns {@code {api, callerClassFilter, callSites[{className, methodName, lineNumber}],
 * count}}.
 */
@Command(name = "call-sites",
		description = "Find all call sites of a given API method name across the APK")
public class CallSitesCommand extends AbstractCommand {

	@Option(names = { "-m", "--method" }, description = "API method name to locate (e.g. 'getDeviceId')", required = true)
	protected String method;

	@Option(names = { "-c", "--class" }, description = "Optional: only count calls whose receiver type contains this name")
	protected String callerClassFilter;

	@Option(names = { "-p", "--package" }, description = "Only scan caller classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of call sites", defaultValue = "200")
	protected int limit = 200;

	/**
	 * Matches an invocation of the target method: a method call is {@code .apiName(} or a
	 * bare {@code apiName(} at statement start (this()/super()-less). We require a preceding
	 * non-identifier char (dot, whitespace, or start) so {@code getDeviceId} doesn't match
	 * {@code myGetDeviceId}.
	 */
	private Pattern callPattern;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.method = (String) args.get("method");
		this.callerClassFilter = (String) args.get("class");
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (method == null || method.isEmpty()) {
			return JsonOutput.error("BadQuery", "--method is required");
		}
		// Build the call pattern now that method is known. Require a word boundary before the
		// name and '(' after (optionally with spaces).
		String name = Pattern.quote(method);
		callPattern = Pattern.compile("(?:^|[^A-Za-z0-9_$])" + name + "\\s*\\(");

		List<Map<String, Object>> sites = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			if (sites.size() >= limit) {
				break;
			}
			String fullName = cls.getFullName();
			if (packageFilter != null && !fullName.startsWith(packageFilter)) {
				continue;
			}
			for (JavaMethod m : cls.getMethods()) {
				if (sites.size() >= limit) {
					break;
				}
				String code;
				try {
					code = m.getCodeStr();
				} catch (Exception e) {
					continue;
				}
				if (code == null || code.isEmpty()) {
					continue;
				}
				String[] lines = code.split("\n", -1);
				for (int i = 0; i < lines.length && sites.size() < limit; i++) {
					Matcher mat = callPattern.matcher(lines[i]);
					if (mat.find()) {
						Map<String, Object> s = new LinkedHashMap<>();
						s.put("className", fullName);
						s.put("methodName", m.getName());
						s.put("lineNumber", i + 1);
						s.put("source", lines[i].trim());
						sites.add(s);
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("api", method);
		data.put("callerClassFilter", callerClassFilter);
		data.put("callSites", sites);
		data.put("count", sites.size());
		data.put("truncated", sites.size() >= limit);
		return JsonOutput.ok(data);
	}

	@Override
	protected String getDaemonCommandName() {
		return "call-sites";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("method", method);
		if (callerClassFilter != null) {
			args.put("class", callerClassFilter);
		}
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
