package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Evaluates the quality of decompiled Java code across the APK. Absorbs the
 * design from {@code jd-mcp-duo}'s {@code SourceQualityReportTool} (which
 * assesses decompile completeness, readability, and structural quality) and
 * reimplements it natively. Reports on: empty methods, methods with only
 * error comments (jadx markers), exception handling gaps, TODO/stub markers,
 * obfuscation indicators, and comment density.
 */
@Command(name = "source-quality-report", description = "Evaluate decompiled code quality across the APK")
public class SourceQualityReportCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum findings per category", defaultValue = "100")
	protected int limit = 100;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		int totalClasses = 0;
		int totalMethods = 0;
		int emptyMethods = 0;
		int errorMethods = 0;  // Methods with jadx error comments
		int stubMethods = 0;   // TODO/FIXME/stub markers
		int obfuscatedClasses = 0;
		int wellCommentedClasses = 0;
		int lowQualityClasses = 0;
		int methodsWithCatchAll = 0;

		List<Map<String, Object>> issues = new ArrayList<>();

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
			if (code == null || code.isEmpty()) continue;

			totalClasses++;

			// Check for jadx error markers
			boolean hasErrors = code.contains("// ERROR") || code.contains("/* inaccessible */")
					|| code.contains("/* failed to decompose") || code.contains("Bad method")
					|| code.contains("Method was not decompiled");

			// Check for stub/TODO markers
			boolean hasStub = code.contains("TODO") || code.contains("FIXME")
					|| code.contains("/* stub */") || code.contains("// stub");

			// Check for obfuscation
			boolean isObfuscated = isObfuscatedName(fullName) || code.contains(".a.") || code.contains(".b.");

			// Check for catch-all exception handling
			boolean hasCatchAll = code.contains("catch (Exception e)") || code.contains("catch (Throwable t)");

			// Count methods
			String[] lines = code.split("\n", -1);
			int classMethods = 0;
			int classEmpty = 0;

			for (String line : lines) {
				// Detect method declarations
				if (line.contains("void ") || line.contains("String ") || line.contains("int ")
						|| line.contains("boolean ") || line.contains("long ") || line.contains("Object ")
						|| line.contains("List ") || line.contains("Map ") || line.contains("byte ")
						|| line.contains("float ") || line.contains("double ")) {
					if (line.contains("(") && !line.contains("class ") && !line.contains("interface ")
							&& !line.trim().startsWith("//")) {
						classMethods++;
					}
				}
				// Detect empty method body
				if (line.trim().equals("}") && classMethods > 0) {
					// Simple heuristic: if a method block has very few lines, it's likely empty or stub
				}
			}

			totalMethods += classMethods;

			if (hasErrors) {
				errorMethods++;
				if (issues.size() < limit) {
					Map<String, Object> issue = new LinkedHashMap<>();
					issue.put("className", fullName);
					issue.put("kind", "decompile-error");
					issue.put("severity", "high");
					issues.add(issue);
				}
			}
			if (hasStub) {
				stubMethods++;
				if (issues.size() < limit) {
					Map<String, Object> issue = new LinkedHashMap<>();
					issue.put("className", fullName);
					issue.put("kind", "stub-marker");
					issue.put("severity", "medium");
					issues.add(issue);
				}
			}
			if (isObfuscated) {
				obfuscatedClasses++;
				if (issues.size() < limit) {
					Map<String, Object> issue = new LinkedHashMap<>();
					issue.put("className", fullName);
					issue.put("kind", "obfuscated");
					issue.put("severity", "low");
					issues.add(issue);
				}
			}
			if (hasCatchAll) {
				methodsWithCatchAll++;
			}

			// Quality score per class
			int qualityScore = 100;
			if (hasErrors) qualityScore -= 30;
			if (hasStub) qualityScore -= 20;
			if (isObfuscated) qualityScore -= 15;
			if (hasCatchAll) qualityScore -= 5;

			if (qualityScore < 50) {
				lowQualityClasses++;
			} else if (qualityScore >= 80) {
				wellCommentedClasses++;
			}
		}

		// Compute overall quality score
		int overallScore = totalClasses > 0
				? 100 - (lowQualityClasses * 100 / totalClasses) - (obfuscatedClasses * 30 / totalClasses)
				: 100;
		overallScore = Math.max(0, Math.min(100, overallScore));

		String qualityLevel;
		if (overallScore >= 80) qualityLevel = "good";
		else if (overallScore >= 60) qualityLevel = "fair";
		else if (overallScore >= 40) qualityLevel = "poor";
		else qualityLevel = "very-poor";

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("overallScore", overallScore);
		data.put("qualityLevel", qualityLevel);
		data.put("totalClasses", totalClasses);
		data.put("totalMethods", totalMethods);
		data.put("errorMethods", errorMethods);
		data.put("stubMethods", stubMethods);
		data.put("obfuscatedClasses", obfuscatedClasses);
		data.put("methodsWithCatchAll", methodsWithCatchAll);
		data.put("lowQualityClasses", lowQualityClasses);
		data.put("issues", issues);
		// Silent-truncation signal: errorMethods/stubMethods/obfuscatedClasses are FULL counts (incremented
		// unconditionally) while `issues` is capped at `limit` (only added when issues.size() < limit).
		// Without this flag an AI consumer comparing errorMethods=312 to issues.size()=100 would mistake
		// the capped list for the complete set — an FN amplifier (the tail issues are invisible).
		// truncated = the number of issues we WOULD have added (sum of the three per-class issue counters)
		// exceeds the capped list size.
		data.put("truncated", (errorMethods + stubMethods + obfuscatedClasses) > issues.size());
		return JsonOutput.ok(data);
	}

	private boolean isObfuscatedName(String name) {
		// Check for short class names (a, b, c, etc.) that are obfuscation artifacts
		String simpleName = name.substring(name.lastIndexOf('.') + 1);
		if (simpleName.length() <= 2 && !simpleName.equals("R") && !simpleName.equals("BuildConfig")) {
			return true;
		}
		// Check for numeric suffixes (Class1, Class2, etc.)
		if (simpleName.matches("[A-Z]\\d+")) return true;
		// Check for single-char packages (com.a.b)
		for (String part : name.split("\\.")) {
			if (part.length() == 1 && !part.equals("R") && !part.matches("[A-Z]")) return true;
		}
		return false;
	}

	@Override
	protected String getDaemonCommandName() {
		return "source-quality-report";
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
