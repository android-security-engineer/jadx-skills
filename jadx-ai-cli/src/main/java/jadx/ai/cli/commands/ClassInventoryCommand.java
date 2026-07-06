package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Produces a comprehensive inventory of all classes, methods, and fields in
 * the APK, grouped by package. Absorbs the design from
 * {@code ai-mobile-reverse-skills} Phase 1 (which generates a
 * {@code file_inventory.json} covering all code artifacts) and
 * {@code jd-mcp-duo}'s {@code ClassMetadataTool} (which inspects class-level
 * metadata, methods, fields, and annotations). This native implementation
 * reads jadx's parsed model and outputs structured statistics.
 */
@Command(name = "class-inventory", description = "Inventory of classes, methods, and fields grouped by package")
public class ClassInventoryCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only include classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--top" }, description = "Top N packages by class count", defaultValue = "20")
	protected int top = 20;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("top")) {
			this.top = ((Number) args.get("top")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		int totalClasses = 0;
		int totalMethods = 0;
		int totalFields = 0;
		Map<String, int[]> packageStats = new TreeMap<>();  // package -> [classCount, methodCount, fieldCount]

		for (JavaClass cls : decompiler.getClasses()) {
			String fullName = cls.getFullName();
			if (packageFilter != null && !fullName.startsWith(packageFilter)) {
				continue;
			}

			totalClasses++;

			// Count methods and fields via code scanning
			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty()) continue;

			// Simple method count: count lines that look like method declarations
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
			String pkg = getTopPackage(fullName);
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

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("totalClasses", totalClasses);
		data.put("totalMethods", totalMethods);
		data.put("totalFields", totalFields);
		data.put("packageCount", packageStats.size());
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
		return "class-inventory";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("top", top);
		return args;
	}
}
