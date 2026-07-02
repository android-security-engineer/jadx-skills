package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Finds <em>orphaned</em> classes — public classes that are never referenced by any other class
 * in the APK (a dead-code / unreached-surface candidate). Approach is a self-contained text
 * cross-reference: gather every class's full name, then for each public class check whether any
 * <em>other</em> class's source mentions its short or full name. Framework and entry classes
 * (Activity/Application/Service/Receiver/Provider/Main, and {@code android.*}/{@code androidx.*}/
 * {@code kotlin.*} packages) are excluded as they are reachable by the framework, not by calls.
 * Absorbs the dead-code/unused-class idea from {@code jd-mcp-duo} in {@code reference/}; a
 * text-level approximation that needs no xref engine. Pairs with {@code entrypoint-scan}
 * (the inverse — where execution starts) and {@code class-inventory}.
 */
@Command(name = "dead-code-report",
		description = "Detect orphaned public classes never referenced by any other class (dead-code candidates)")
public class DeadCodeReportCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum orphan candidates to report", defaultValue = "50")
	protected int limit = 50;

	private static final Set<String> FRAMEWORK_PREFIXES = Set.of(
			"android.", "androidx.", "com.android.", "com.google.android.",
			"dalvik.", "java.", "javax.", "kotlin.", "kotlinx.",
			"org.w3c.", "org.xml.", "org.json.", "sun.", "com.sun.");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		// Pass 1: collect class names + code.
		List<String> fullNames = new ArrayList<>();
		List<String> shortNames = new ArrayList<>();
		List<String> codes = new ArrayList<>();
		List<Boolean> isPublic = new ArrayList<>();
		for (JavaClass cls : decompiler.getClasses()) {
			String full = cls.getFullName();
			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null) {
				continue;
			}
			fullNames.add(full);
			shortNames.add(shortName(full));
			codes.add(code);
			isPublic.add(isPublicClass(code, full));
		}

		// Pass 2: for each public non-framework non-entry class, count refs in other classes.
		List<Map<String, Object>> orphans = new ArrayList<>();
		int checked = 0;
		for (int i = 0; i < fullNames.size(); i++) {
			if (!isPublic.get(i)) {
				continue;
			}
			String full = fullNames.get(i);
			if (isFramework(full) || isEntryClass(shortNames.get(i))) {
				continue;
			}
			checked++;
			String full2 = fullNames.get(i);
			String short2 = shortNames.get(i);
			int refs = 0;
			for (int j = 0; j < codes.size(); j++) {
				if (j == i) {
					continue;
				}
				String other = codes.get(j);
				// Reference via fully-qualified name is the strong signal.
				if (other.indexOf(full2) >= 0) {
					refs++;
					break;
				}
				// Short name as a word boundary (cheap and avoids substring false positives
				// like "Util" inside "Utilities").
				if (refs == 0 && wordContains(other, short2)) {
					refs++;
				}
			}
			if (refs == 0) {
				Map<String, Object> o = new LinkedHashMap<>();
				o.put("className", full);
				o.put("shortName", short2);
				o.put("reason", "no references found in any other class");
				orphans.add(o);
				if (orphans.size() >= limit) {
					break;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("totalClasses", fullNames.size());
		data.put("publicClassesChecked", checked);
		data.put("orphanCandidateCount", orphans.size());
		data.put("orphanCandidates", orphans);
		// Silent-truncation signal: the orphan scan breaks at `orphans.size() >= limit`, so a large app
		// silently drops tail orphans. totalClasses/publicClassesChecked are full counts (computed before
		// the cap); without this flag the AI mistakes the capped list for complete — an FN amplifier.
		data.put("truncated", orphans.size() >= limit);
		data.put("note", "Text cross-reference approximation; entry/framework classes excluded. "
				+ "Reflection/manifest-only reachability can cause false positives.");
		return JsonOutput.ok(data);
	}

	private static String shortName(String full) {
		int dot = full.lastIndexOf('.');
		int dollar = full.lastIndexOf('$');
		int cut = Math.max(dot, dollar);
		return cut < 0 ? full : full.substring(cut + 1);
	}

	private static boolean isPublicClass(String code, String full) {
		// Look at the class declaration line.
		for (String line : code.split("\n", -1)) {
			String t = line.trim();
			if (t.startsWith("public ") && (t.contains("class ") || t.contains("interface ")
					|| t.contains("enum ") || t.contains("record "))) {
				return true;
			}
		}
		return false;
	}

	private static boolean isFramework(String full) {
		for (String p : FRAMEWORK_PREFIXES) {
			if (full.startsWith(p)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isEntryClass(String shortName) {
		// Framework-reachable component shapes (manifest can name these directly).
		return shortName.endsWith("Activity") || shortName.endsWith("Fragment")
				|| shortName.endsWith("Service") || shortName.endsWith("Receiver")
				|| shortName.endsWith("Provider") || shortName.endsWith("Application")
				|| shortName.equals("Main") || shortName.endsWith("Application")
				|| shortName.endsWith("Activity")
				|| shortName.endsWith("BroadcastReceiver") || shortName.endsWith("ContentProvider")
				|| shortName.endsWith("IntentService") || shortName.endsWith("JobService")
				|| shortName.endsWith("Activity");
	}

	private static boolean wordContains(String text, String token) {
		if (token == null || token.isEmpty()) {
			return false;
		}
		int idx = text.indexOf(token);
		while (idx >= 0) {
			char before = idx > 0 ? text.charAt(idx - 1) : ' ';
			int end = idx + token.length();
			char after = end < text.length() ? text.charAt(end) : ' ';
			if (!isIdentChar(before) && !isIdentChar(after)
					&& before != '.' && before != '$') {
				return true;
			}
			idx = text.indexOf(token, idx + 1);
		}
		return false;
	}

	private static boolean isIdentChar(char c) {
		return Character.isLetterOrDigit(c) || c == '_' || c == '$';
	}

	@Override
	protected String getDaemonCommandName() {
		return "dead-code-report";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("limit", limit);
		return args;
	}
}
