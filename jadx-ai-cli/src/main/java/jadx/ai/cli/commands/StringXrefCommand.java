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
 * Reverse string lookup: given a string literal, find the classes and methods that embed it.
 * {@code search --type string} returns the matching <em>source line</em> (whole line, class
 * level only) — it cannot point at the exact method and it mixes in non-literal hits
 * (identifiers, comments). This command walks {@link JavaMethod#getCodeStr()} per method,
 * extracts genuine {@code "..."} string literals, and reports each reference with its
 * declaring class + method + the literal value — the answer to "where is this URL / key /
 * magic string used?". Absorbed from {@code dex-analyzer-for-llm}'s
 * {@code find_classes_using_strings / find_methods_using_strings} (DexKit value-string index)
 * — same query, native.
 *
 * <p>Returns {@code {query, matchType, references[{className, methodName, literalValue}],
 * count}}.
 */
@Command(name = "string-xref",
		description = "Find classes/methods that embed a given string literal (reverse string lookup)")
public class StringXrefCommand extends AbstractCommand {

	@Option(names = { "-q", "--query" }, description = "String literal to locate (repeatable)", required = true)
	protected List<String> queries;

	@Option(names = { "--exact" }, description = "Exact literal match instead of substring")
	protected boolean exact;

	@Option(names = { "-i", "--ignore-case" }, description = "Case-insensitive matching")
	protected boolean ignoreCase;

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of references", defaultValue = "200")
	protected int limit = 200;

	/** Matches a Java string literal, honoring backslash escapes, excluding char literals. */
	private static final Pattern STRING_LITERAL = Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		Object q = args.get("query");
		if (q instanceof List) {
			this.queries = new ArrayList<>();
			for (Object o : (List<?>) q) {
				this.queries.add(String.valueOf(o));
			}
		} else if (q != null) {
			this.queries = new ArrayList<>();
			this.queries.add(String.valueOf(q));
		}
		this.exact = Boolean.TRUE.equals(args.get("exact"));
		this.ignoreCase = Boolean.TRUE.equals(args.get("ignore-case"));
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (queries == null || queries.isEmpty()) {
			return JsonOutput.error("BadQuery", "At least one --query is required");
		}
		List<String> normQueries = new ArrayList<>();
		for (String q : queries) {
			normQueries.add(ignoreCase ? q.toLowerCase() : q);
		}

		List<Map<String, Object>> refs = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			if (refs.size() >= limit) {
				break;
			}
			String fullName = cls.getFullName();
			if (packageFilter != null && !fullName.startsWith(packageFilter)) {
				continue;
			}
			for (JavaMethod m : cls.getMethods()) {
				if (refs.size() >= limit) {
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
				Matcher mat = STRING_LITERAL.matcher(code);
				while (mat.find() && refs.size() < limit) {
					String lit = mat.group();
					// Strip the surrounding quotes for matching.
					String inner = lit.substring(1, lit.length() - 1);
					String matched = matchAgainst(inner, normQueries, exact, ignoreCase);
					if (matched == null) {
						continue;
					}
					Map<String, Object> r = new LinkedHashMap<>();
					r.put("className", fullName);
					r.put("methodName", m.getName());
					r.put("literalValue", inner);
					refs.add(r);
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("query", queries);
		data.put("matchType", exact ? "exact" : "contains");
		data.put("references", refs);
		data.put("count", refs.size());
		data.put("truncated", refs.size() >= limit);
		return JsonOutput.ok(data);
	}

	/** Returns the query that matched (for multi-query), or null if none. */
	private static String matchAgainst(String literal, List<String> queries, boolean exact, boolean ignoreCase) {
		String l = ignoreCase ? literal.toLowerCase() : literal;
		for (String q : queries) {
			if (exact) {
				if (l.equals(q)) {
					return q;
				}
			} else if (l.contains(q)) {
				return q;
			}
		}
		return null;
	}

	@Override
	protected String getDaemonCommandName() {
		return "string-xref";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("query", queries);
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
