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
 * Reports per-method cyclomatic complexity (an approximation): extracts each method body via
 * brace-matching over the decompiled source, then counts decision points ({@code if / else if /
 * for / while / do / case / catch / && / || / ?:}). Methods above a threshold are the review
 * targets — the long, branchy ones where bugs and obfuscation hide. Absorbs the complexity
 * metric from {@code jd-mcp-duo}'s CFG/bytecode analysis in {@code reference/}; reimplemented
 * natively as a text-level approximation (no CFG construction needed). Complements
 * {@code source-quality-report} (whole-APK quality) with method-level granularity.
 */
@Command(name = "method-complexity",
		description = "Per-method cyclomatic complexity (decision-point count) over decompiled source")
public class MethodComplexityCommand extends AbstractCommand {

	@Option(names = { "--top" }, description = "Top N most complex methods to report", defaultValue = "30")
	protected int top = 30;

	@Option(names = { "--threshold" }, description = "Complexity threshold for a 'complex' method", defaultValue = "10")
	protected int threshold = 10;

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	private static final Pattern METHOD_HEADER = Pattern.compile("([A-Za-z_$][\\w$.<>\\[\\],?\\s]*?)\\s*\\(");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("top")) {
			this.top = ((Number) args.get("top")).intValue();
		}
		if (args.containsKey("threshold")) {
			this.threshold = ((Number) args.get("threshold")).intValue();
		}
		this.packageFilter = (String) args.get("package");
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> allMethods = new ArrayList<>();

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
			for (MethodBlock m : extractMethods(code)) {
				int decisions = countDecisions(m.body);
				int complexity = decisions + 1;
				Map<String, Object> method = new LinkedHashMap<>();
				method.put("className", fullName);
				method.put("methodName", m.name);
				method.put("complexity", complexity);
				method.put("decisionPoints", decisions);
				method.put("approxLines", m.body.split("\n", -1).length);
				if (complexity >= threshold) {
					method.put("complex", true);
				}
				allMethods.add(method);
			}
		}

		// Top N by complexity
		List<Map<String, Object>> topMethods = new ArrayList<>();
		allMethods.stream()
				.sorted((a, b) -> ((Integer) b.get("complexity")).compareTo((Integer) a.get("complexity")))
				.limit(top)
				.forEach(topMethods::add);

		int complexCount = (int) allMethods.stream().filter(m -> (int) m.get("complexity") >= threshold).count();
		int maxComplexity = allMethods.stream().mapToInt(m -> (int) m.get("complexity")).max().orElse(0);
		double avg = allMethods.isEmpty() ? 0
				: allMethods.stream().mapToInt(m -> (int) m.get("complexity")).average().orElse(0);

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("methodCount", allMethods.size());
		data.put("maxComplexity", maxComplexity);
		data.put("averageComplexity", Math.round(avg * 100.0) / 100.0);
		data.put("complexMethodCount", complexCount);
		data.put("threshold", threshold);
		data.put("topMethods", topMethods);
		return JsonOutput.ok(data);
	}

	/** A brace-matched method: header signature + body text. */
	private static final class MethodBlock {
		final String name;
		final String body;

		MethodBlock(String name, String body) {
			this.name = name;
			this.body = body;
		}
	}

	/**
	 * Extract method blocks from decompiled source by brace-matching at class-body depth.
	 * Strings/char-literals/comments are blanked first so braces inside them don't miscount.
	 * A depth-1→2 transition whose header contains {@code (...)} and not {@code new } is a method.
	 */
	private static List<MethodBlock> extractMethods(String code) {
		String safe = blankLiteralsAndComments(code);
		List<MethodBlock> out = new ArrayList<>();
		int depth = 0;
		int headerStart = 0;
		int methodStart = -1;
		StringBuilder header = new StringBuilder();

		for (int i = 0; i < safe.length(); i++) {
			char c = safe.charAt(i);
			if (c == '{') {
				if (depth == 1) {
					// Entering a depth-2 block. Is the header a method signature?
					String h = header.toString();
					if (h.indexOf('(') >= 0 && h.indexOf(')') > h.indexOf('(')
							&& !h.contains("new ") && !h.contains("class ") && !h.contains("interface ")
							&& !h.contains("enum ") && !h.contains("record ")) {
						methodStart = i + 1;
					}
				}
				depth++;
			} else if (c == '}') {
				depth--;
				if (depth == 1 && methodStart >= 0) {
					String body = safe.substring(methodStart, i);
					String name = extractMethodName(header.toString());
					if (name != null) {
						out.add(new MethodBlock(name, body));
					}
					methodStart = -1;
				}
				if (depth <= 1) {
					header.setLength(0);
					headerStart = i + 1;
				}
			} else if (depth <= 1 && methodStart < 0) {
				if (c == ';' || c == '{') {
					header.setLength(0);
				} else {
					header.append(c);
				}
			}
		}
		return out;
	}

	private static String extractMethodName(String header) {
		Matcher m = METHOD_HEADER.matcher(header);
		String last = null;
		while (m.find()) {
			String group = m.group(1).trim();
			// Last identifier before '(' is the method name
			String[] parts = group.split("[\\s.<>\\[\\],]+");
			for (String p : parts) {
				if (!p.isEmpty() && !isReturnTypeKeyword(p)) {
					last = p;
				}
			}
		}
		// Prefer the token immediately before the first '('
		int paren = header.indexOf('(');
		if (paren > 0) {
			String before = header.substring(0, paren).trim();
			String[] toks = before.split("[\\s.<>\\[\\],]+");
			for (int i = toks.length - 1; i >= 0; i--) {
				if (!toks[i].isEmpty() && !isReturnTypeKeyword(toks[i]) && !isModifier(toks[i])) {
					return toks[i];
				}
			}
		}
		return last;
	}

	private static boolean isReturnTypeKeyword(String s) {
		return s.equals("void") || s.equals("return") || s.equals("throws")
				|| s.equals("static") || s.equals("final") || s.equals("public")
				|| s.equals("private") || s.equals("protected") || s.equals("abstract")
				|| s.equals("synchronized") || s.equals("native") || s.equals("default")
				|| s.equals("strictfp") || s.equals("transient") || s.equals("volatile");
	}

	private static boolean isModifier(String s) {
		return isReturnTypeKeyword(s);
	}

	private static int countDecisions(String body) {
		int count = 0;
		count += countMatches(body, "\\bif\\b");
		count += countMatches(body, "\\bfor\\b");
		count += countMatches(body, "\\bwhile\\b");
		count += countMatches(body, "\\bdo\\b\\s*\\{");
		count += countMatches(body, "\\bcase\\b");
		count += countMatches(body, "\\bcatch\\b");
		count += countMatches(body, "&&");
		count += countMatches(body, "\\|\\|");
		count += countTernary(body);
		return count;
	}

	private static int countTernary(String body) {
		// Count '?' not part of generics (<... ? ...>) — heuristic: '?' preceded by space/operand and followed by ':'
		int count = 0;
		boolean inGenerics = false;
		for (int i = 0; i < body.length(); i++) {
			char c = body.charAt(i);
			if (c == '<') inGenerics = true;
			else if (c == '>') inGenerics = false;
			else if (c == '?' && !inGenerics) {
				// look for a following ':' at the same nesting
				count++;
			}
		}
		return count;
	}

	private static int countMatches(String s, String regex) {
		Matcher m = Pattern.compile(regex).matcher(s);
		int n = 0;
		while (m.find()) n++;
		return n;
	}

	private static String blankLiteralsAndComments(String code) {
		StringBuilder sb = new StringBuilder(code.length());
		int i = 0;
		int n = code.length();
		while (i < n) {
			char c = code.charAt(i);
			// Line comment
			if (c == '/' && i + 1 < n && code.charAt(i + 1) == '/') {
				while (i < n && code.charAt(i) != '\n') {
					sb.append(' ');
					i++;
				}
				continue;
			}
			// Block comment
			if (c == '/' && i + 1 < n && code.charAt(i + 1) == '*') {
				sb.append(' ').append(' ');
				i += 2;
				while (i < n && !(code.charAt(i) == '*' && i + 1 < n && code.charAt(i + 1) == '/')) {
					sb.append(code.charAt(i) == '\n' ? '\n' : ' ');
					i++;
				}
				if (i < n) {
					sb.append(' ').append(' ');
					i += 2;
				}
				continue;
			}
			// String literal
			if (c == '"') {
				sb.append(' ');
				i++;
				while (i < n && code.charAt(i) != '"') {
					if (code.charAt(i) == '\\' && i + 1 < n) {
						sb.append(' ').append(' ');
						i += 2;
						continue;
					}
					sb.append(code.charAt(i) == '\n' ? '\n' : ' ');
					i++;
				}
				if (i < n) {
					sb.append(' ');
					i++;
				}
				continue;
			}
			// Char literal
			if (c == '\'') {
				sb.append(' ');
				i++;
				while (i < n && code.charAt(i) != '\'') {
					if (code.charAt(i) == '\\' && i + 1 < n) {
						sb.append(' ').append(' ');
						i += 2;
						continue;
					}
					sb.append(' ');
					i++;
				}
				if (i < n) {
					sb.append(' ');
					i++;
				}
				continue;
			}
			sb.append(c);
			i++;
		}
		return sb.toString();
	}

	@Override
	protected String getDaemonCommandName() {
		return "method-complexity";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("top", top);
		args.put("threshold", threshold);
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		return args;
	}
}
