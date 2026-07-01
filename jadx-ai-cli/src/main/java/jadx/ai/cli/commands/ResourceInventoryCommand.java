package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import picocli.CommandLine.Command;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;

/**
 * Inventories APK resources by category: the {@code res/} sub-directories (layout, drawable,
 * values, raw, font, mipmap, menu, anim, xml, color), {@code assets/}, native {@code lib/},
 * {@code META-INF/}, code ({@code .dex}/classes), and the rest. Each entry is a count so an
 * analyst can size the attack surface (raw assets, bundled fonts, native libs) without paging
 * through the resource tree. Absorbs the resource-classification design from
 * {@code dex-analyzer-for-llm} in {@code reference/}; native over jadx's resource model.
 * Complements {@code resources} (filter/read) and {@code native-libs} (deep .so analysis).
 */
@Command(name = "resource-inventory",
		description = "Inventory APK resources by category (res/ subdirs, assets, lib, META-INF, dex) with counts")
public class ResourceInventoryCommand extends AbstractCommand {

	@Override
	protected void applyArgs(Map<String, Object> args) {
		// No options.
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		Map<String, int[]> categoryCounts = new TreeMap<>();  // category -> [count]
		Map<String, Integer> byExtension = new TreeMap<>();
		int total = 0;

		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name == null) {
				continue;
			}
			String path = name.replace('\\', '/');
			total++;
			String cat = categorize(path);
			categoryCounts.computeIfAbsent(cat, k -> new int[1])[0]++;

			int dot = path.lastIndexOf('.');
			if (dot > 0 && dot < path.length() - 1) {
				String ext = path.substring(dot + 1).toLowerCase();
				byExtension.merge(ext, 1, Integer::sum);
			}
		}

		List<Map<String, Object>> categories = new ArrayList<>();
		categoryCounts.entrySet().stream()
				.sorted((a, b) -> b.getValue()[0] - a.getValue()[0])
				.forEach(e -> {
					Map<String, Object> c = new LinkedHashMap<>();
					c.put("category", e.getKey());
					c.put("count", e.getValue()[0]);
					categories.add(c);
				});

		List<Map<String, Object>> topExtensions = new ArrayList<>();
		byExtension.entrySet().stream()
				.sorted((a, b) -> b.getValue() - a.getValue())
				.limit(25)
				.forEach(e -> {
					Map<String, Object> x = new LinkedHashMap<>();
					x.put("extension", e.getKey());
					x.put("count", e.getValue());
					topExtensions.add(x);
				});

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("totalResources", total);
		data.put("categories", categories);
		data.put("topExtensions", topExtensions);
		return JsonOutput.ok(data);
	}

	private static String categorize(String path) {
		String lower = path.toLowerCase();
		if (lower.startsWith("res/layout")) return "res/layout";
		if (lower.startsWith("res/drawable")) return "res/drawable";
		if (lower.startsWith("res/mipmap")) return "res/mipmap";
		if (lower.startsWith("res/values")) return "res/values";
		if (lower.startsWith("res/raw")) return "res/raw";
		if (lower.startsWith("res/font")) return "res/font";
		if (lower.startsWith("res/menu")) return "res/menu";
		if (lower.startsWith("res/anim")) return "res/anim";
		if (lower.startsWith("res/xml")) return "res/xml";
		if (lower.startsWith("res/color")) return "res/color";
		if (lower.startsWith("res/")) return "res/other";
		if (lower.startsWith("assets/")) return "assets";
		if (lower.startsWith("lib/")) return "lib (native)";
		if (lower.startsWith("meta-inf/")) return "META-INF";
		if (lower.startsWith("kotlin/")) return "kotlin";
		if (lower.endsWith(".dex") || lower.contains("classes")) return "code (dex)";
		if (lower.endsWith(".so")) return "native (.so)";
		return "other";
	}

	@Override
	protected String getDaemonCommandName() {
		return "resource-inventory";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		return new LinkedHashMap<>();
	}
}
