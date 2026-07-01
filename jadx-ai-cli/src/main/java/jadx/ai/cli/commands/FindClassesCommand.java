package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.core.dex.instructions.args.ArgType;
import jadx.core.dex.nodes.ClassNode;

/**
 * Structured class lookup by {@code extends}, {@code implements}, or {@code @annotation} —
 * queries the type hierarchy directly rather than free-text searching the decompiled source.
 * {@code search --type class} matches class <em>names</em>; it cannot answer "which classes
 * subclass {@code Activity}" or "which are annotated {@code @JavascriptInterface}". This
 * command does: super-class and implemented interfaces are read from the parsed
 * {@link ClassNode} (ground truth, not text), and annotations are matched against the
 * decompiled {@code @Ann} markers jadx renders. Absorbed from {@code dex-analyzer-for-llm}'s
 * {@code find_classes_by_super / _implementing / _annotation} (DexKit-backed) — same queries,
 * native.
 *
 * <p>Returns {@code {by, query, matches[{className, superClass, interfaces}], count}}.
 */
@Command(name = "find-classes",
		description = "Find classes by superclass, implemented interface, or annotation")
public class FindClassesCommand extends AbstractCommand {

	@Option(names = { "--by" }, description = "Query dimension: super, interface, annotation", required = true)
	protected String by;

	@Option(names = { "-q", "--query" }, description = "Target super/interface/annotation name (substring or exact)", required = true)
	protected String query;

	@Option(names = { "--exact" }, description = "Exact name match instead of substring")
	protected boolean exact;

	@Option(names = { "-i", "--ignore-case" }, description = "Case-insensitive matching")
	protected boolean ignoreCase;

	@Option(names = { "-p", "--package" }, description = "Only match classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of matches", defaultValue = "100")
	protected int limit = 100;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.by = (String) args.get("by");
		this.query = (String) args.get("query");
		this.exact = Boolean.TRUE.equals(args.get("exact"));
		this.ignoreCase = Boolean.TRUE.equals(args.get("ignore-case"));
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		String dim = by == null ? "" : by.toLowerCase();
		if (!dim.equals("super") && !dim.equals("interface") && !dim.equals("annotation")) {
			return JsonOutput.error("BadQuery",
					"--by must be one of: super, interface, annotation");
		}
		if (query == null || query.isEmpty()) {
			return JsonOutput.error("BadQuery", "--query is required");
		}

		List<Map<String, Object>> matches = new ArrayList<>();
		String q = ignoreCase ? query.toLowerCase() : query;

		for (JavaClass cls : decompiler.getClasses()) {
			if (matches.size() >= limit) {
				break;
			}
			String fullName = cls.getFullName();
			if (packageFilter != null && !fullName.startsWith(packageFilter)) {
				continue;
			}
			if (dim.equals("annotation")) {
				// Annotation match: scan decompiled code for @<name> markers jadx renders.
				String code;
				try {
					code = cls.getCode();
				} catch (Exception e) {
					continue;
				}
				if (code == null || code.isEmpty()) {
					continue;
				}
				if (!hasAnnotation(code, query, exact, ignoreCase)) {
					continue;
				}
			} else {
				ClassNode cn = cls.getClassNode();
				if (dim.equals("super")) {
					ArgType superType = cn.getSuperClass();
					if (superType == null || !nameMatches(typeName(superType), q, exact, ignoreCase)) {
						continue;
					}
				} else { // interface
					List<ArgType> ifaces = cn.getInterfaces();
					boolean found = false;
					if (ifaces != null) {
						for (ArgType it : ifaces) {
							if (nameMatches(typeName(it), q, exact, ignoreCase)) {
								found = true;
								break;
							}
						}
					}
					if (!found) {
						continue;
					}
				}
			}
			matches.add(classInfo(cls));
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("by", dim);
		data.put("query", query);
		data.put("matches", matches);
		data.put("count", matches.size());
		data.put("truncated", matches.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> classInfo(JavaClass cls) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("className", cls.getFullName());
		ClassNode cn = cls.getClassNode();
		ArgType sup = cn.getSuperClass();
		m.put("superClass", sup == null ? null : typeName(sup));
		List<ArgType> ifaces = cn.getInterfaces();
		List<String> ifaceNames = new ArrayList<>();
		if (ifaces != null) {
			for (ArgType it : ifaces) {
				ifaceNames.add(typeName(it));
			}
		}
		m.put("interfaces", ifaceNames);
		return m;
	}

	private static String typeName(ArgType t) {
		if (t == null) {
			return null;
		}
		// ArgType.toString() yields the Java form (e.g. "android.app.Activity") for object types.
		return t.toString();
	}

	private static boolean nameMatches(String candidate, String queryLower, boolean exact, boolean ignoreCase) {
		if (candidate == null) {
			return false;
		}
		String c = ignoreCase ? candidate.toLowerCase() : candidate;
		String q = ignoreCase ? queryLower.toLowerCase() : queryLower;
		return exact ? c.equals(q) : c.contains(q);
	}

	private static boolean hasAnnotation(String code, String annName, boolean exact, boolean ignoreCase) {
		// jadx renders annotations as @Name or @pkg.Name on the class/method declaration.
		// Match @<annName> optionally followed by ( or a word boundary, ignoring case if asked.
		String name = Pattern.quote(annName);
		String re = "@" + name + "(?:\\s*\\(|\\b)";
		int flags = ignoreCase ? Pattern.CASE_INSENSITIVE : 0;
		return Pattern.compile(re, flags).matcher(code).find();
	}

	@Override
	protected String getDaemonCommandName() {
		return "find-classes";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("by", by);
		args.put("query", query);
		if (exact) {
			args.put("exact", true);
		}
		if (ignoreCase) {
			args.put("ignore-case", true);
		}
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
