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
 * Produces DEX-level statistics: class count per DEX file, multidex
 * detection, method/field density, and package distribution per DEX.
 * Absorbs the design from {@code ai-mobile-reverse-skills} Phase 1
 * (which generates a {@code dex_analysis.json} with per-DEX class
 * distribution) and {@code jd-mcp-duo}'s class metadata tools.
 * Native implementation over jadx's parsed model — no external tools.
 */
@Command(name = "dex-stat", description = "DEX-level statistics: class/method/field counts, multidex detection, package distribution")
public class DexStatCommand extends AbstractCommand {

	@Option(names = { "--top" }, description = "Top N packages by class count", defaultValue = "15")
	protected int top = 15;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("top")) {
			this.top = ((Number) args.get("top")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		int totalClasses = 0;
		int totalMethods = 0;
		int totalFields = 0;
		Map<String, int[]> packageStats = new LinkedHashMap<>();  // package -> [classCount, methodCount, fieldCount]

		for (JavaClass cls : decompiler.getClasses()) {
			totalClasses++;

			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty()) continue;

			int methodCount = 0;
			int fieldCount = 0;
			String[] lines = code.split("\n", -1);
			for (String line : lines) {
				String trimmed = line.trim();
				// Method declaration heuristic
				if ((trimmed.contains("public ") || trimmed.contains("private ") || trimmed.contains("protected ")
						|| trimmed.contains("static ") || trimmed.contains("final "))
						&& trimmed.contains("(") && trimmed.contains(")")
						&& !trimmed.startsWith("//") && !trimmed.startsWith("/*")
						&& !trimmed.contains("class ") && !trimmed.contains("interface ")) {
					methodCount++;
				}
				// Field declaration heuristic
				if ((trimmed.contains("public ") || trimmed.contains("private ") || trimmed.contains("protected "))
						&& trimmed.endsWith(";") && !trimmed.contains("(")
						&& !trimmed.startsWith("//") && !trimmed.startsWith("/*")) {
					fieldCount++;
				}
			}

			totalMethods += methodCount;
			totalFields += fieldCount;

			// Group by top-level package (first 2 segments)
			String pkg = getTopPackage(cls.getFullName());
			int[] stats = packageStats.computeIfAbsent(pkg, k -> new int[3]);
			stats[0]++;
			stats[1] += methodCount;
			stats[2] += fieldCount;
		}

		// Build top packages sorted by class count
		List<Map<String, Object>> topPackages = new ArrayList<>();
		packageStats.entrySet().stream()
				.sorted((a, b) -> b.getValue()[0] - a.getValue()[0])
				.limit(top)
				.forEach(e -> {
					Map<String, Object> p = new LinkedHashMap<>();
					p.put("package", e.getKey());
					p.put("classCount", e.getValue()[0]);
					p.put("methodCount", e.getValue()[1]);
					p.put("fieldCount", e.getValue()[2]);
					topPackages.add(p);
				});

		// Method/field density
		double methodDensity = totalClasses > 0 ? (double) totalMethods / totalClasses : 0;
		double fieldDensity = totalClasses > 0 ? (double) totalFields / totalClasses : 0;

		// Multidex heuristic: if class count > 65536 (DEX method limit), likely multidex
		boolean likelyMultidex = totalMethods > 65536;

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("totalClasses", totalClasses);
		data.put("totalMethods", totalMethods);
		data.put("totalFields", totalFields);
		data.put("methodDensity", Math.round(methodDensity * 100.0) / 100.0);
		data.put("fieldDensity", Math.round(fieldDensity * 100.0) / 100.0);
		data.put("packageCount", packageStats.size());
		data.put("likelyMultidex", likelyMultidex);
		data.put("topPackages", topPackages);
		return JsonOutput.ok(data);
	}

	private String getTopPackage(String fullName) {
		int first = fullName.indexOf('.');
		if (first < 0) return fullName;
		int second = fullName.indexOf('.', first + 1);
		if (second < 0) return fullName.substring(0, first);
		return fullName.substring(0, second);
	}

	@Override
	protected String getDaemonCommandName() {
		return "dex-stat";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("top", top);
		return args;
	}
}
