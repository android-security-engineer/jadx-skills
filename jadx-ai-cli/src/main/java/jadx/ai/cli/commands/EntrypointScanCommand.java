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
import jadx.api.ResourceFile;

/**
 * Discovers APK entry points: Application subclasses, launcher Activities,
 * ContentProviders, BroadcastReceivers, Services, and static initializers.
 * Absorbs the Phase 1 reconnaissance design from
 * {@code ai-mobile-reverse-skills} (which generates an "entrypoints" report
 * covering manifest-declared components and code-level entry hooks) and
 * reimplements it natively over jadx's manifest parser and class model.
 */
@Command(name = "entrypoint-scan", description = "Discover APK entry points (Application, Activities, Providers, Receivers, Services)")
public class EntrypointScanCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum entry points per category", defaultValue = "50")
	protected int limit = 50;

	private static final Pattern APP_CLASS = Pattern.compile("android:name\\s*=\\s*\"([^\"]+)\"[^>]*>\\s*<intent-filter>|android:name\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern MANIFEST_COMPONENT = Pattern.compile("<(activity|service|receiver|provider)[^>]*android:name\\s*=\\s*\"([^\"]+)\"[^>]*(android:exported\\s*=\\s*\"([^\"]+)\"|)[^>]*>");
	private static final Pattern LAUNCHER_FILTER = Pattern.compile("android.intent.category.LAUNCHER");
	private static final Pattern MAIN_ACTION = Pattern.compile("android.intent.action.MAIN");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> entrypoints = new ArrayList<>();

		// 1. Parse AndroidManifest.xml for declared components
		String manifestXml = null;
		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name != null && name.replace('\\', '/').endsWith("AndroidManifest.xml")) {
				try {
					manifestXml = res.loadContent().getText().toString();
				} catch (Exception e) {
					// Skip
				}
				break;
			}
		}

		if (manifestXml != null) {
			scanManifestEntrypoints(manifestXml, entrypoints);
		}

		// 2. Scan code for Application subclasses
		for (JavaClass cls : decompiler.getClasses()) {
			String fullName = cls.getFullName();
			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty()) continue;

			// Application subclass
			if (code.contains("extends Application") && !fullName.startsWith("android.")) {
				if (entrypoints.stream().noneMatch(e -> "application".equals(e.get("kind")) && fullName.equals(e.get("className")))) {
					Map<String, Object> ep = new LinkedHashMap<>();
					ep.put("kind", "application");
					ep.put("className", fullName);
					ep.put("source", "code-analysis");
					if (entrypoints.size() < limit * 4) entrypoints.add(ep);
				}
			}

			// Static initializer (clinit)
			if (code.contains("static {") || code.contains("static\n{")) {
				if (entrypoints.stream().noneMatch(e -> "static-init".equals(e.get("kind")) && fullName.equals(e.get("className")))) {
					Map<String, Object> ep = new LinkedHashMap<>();
					ep.put("kind", "static-init");
					ep.put("className", fullName);
					ep.put("source", "code-analysis");
					ep.put("note", "Class has static initializer block — runs when class is loaded");
					if (entrypoints.size() < limit * 4) entrypoints.add(ep);
				}
			}

			// JNI loadLibrary
			if (code.contains("System.loadLibrary(") || code.contains("System.load(")) {
				Map<String, Object> ep = new LinkedHashMap<>();
				ep.put("kind", "jni-load");
				ep.put("className", fullName);
				ep.put("source", "code-analysis");
				if (entrypoints.size() < limit * 4) entrypoints.add(ep);
			}
		}

		// Categorize entrypoints
		Map<String, List<Map<String, Object>>> byKind = new LinkedHashMap<>();
		for (Map<String, Object> ep : entrypoints) {
			String kind = (String) ep.get("kind");
			byKind.computeIfAbsent(kind, k -> new ArrayList<>()).add(ep);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("entrypoints", entrypoints);
		data.put("entrypointCount", entrypoints.size());
		data.put("byKind", byKind);
		data.put("hasManifest", manifestXml != null);
		return JsonOutput.ok(data);
	}

	private void scanManifestEntrypoints(String xml, List<Map<String, Object>> entrypoints) {
		// Application class
		Matcher appM = Pattern.compile("<application[^>]*android:name\\s*=\\s*\"([^\"]+)\"").matcher(xml);
		if (appM.find()) {
			Map<String, Object> ep = new LinkedHashMap<>();
			ep.put("kind", "application");
			ep.put("className", appM.group(1));
			ep.put("source", "manifest");
			entrypoints.add(ep);
		}

		// Launcher activities (with MAIN+LAUNCHER intent filter)
		String[] blocks = xml.split("<activity");
		for (int i = 1; i < blocks.length; i++) {
			String block = "<activity" + blocks[i];
			// Check for MAIN + LAUNCHER
			boolean hasMain = MAIN_ACTION.matcher(block).find();
			boolean hasLauncher = LAUNCHER_FILTER.matcher(block).find();
			if (hasMain && hasLauncher) {
				Matcher nameM = Pattern.compile("android:name\\s*=\\s*\"([^\"]+)\"").matcher(block);
				if (nameM.find()) {
					Map<String, Object> ep = new LinkedHashMap<>();
					ep.put("kind", "launcher-activity");
					ep.put("className", nameM.group(1));
					ep.put("source", "manifest");
					ep.put("note", "Main launcher activity — app entry point");
					entrypoints.add(ep);
				}
			}
		}

		// Services
		blocks = xml.split("<service");
		for (int i = 1; i < blocks.length; i++) {
			Matcher nameM = Pattern.compile("android:name\\s*=\\s*\"([^\"]+)\"").matcher(blocks[i]);
			if (nameM.find()) {
				Map<String, Object> ep = new LinkedHashMap<>();
				ep.put("kind", "service");
				ep.put("className", nameM.group(1));
				ep.put("source", "manifest");
				entrypoints.add(ep);
			}
		}

		// Broadcast receivers
		blocks = xml.split("<receiver");
		for (int i = 1; i < blocks.length; i++) {
			Matcher nameM = Pattern.compile("android:name\\s*=\\s*\"([^\"]+)\"").matcher(blocks[i]);
			if (nameM.find()) {
				Map<String, Object> ep = new LinkedHashMap<>();
				ep.put("kind", "receiver");
				ep.put("className", nameM.group(1));
				ep.put("source", "manifest");
				entrypoints.add(ep);
			}
		}

		// Content providers
		blocks = xml.split("<provider");
		for (int i = 1; i < blocks.length; i++) {
			Matcher nameM = Pattern.compile("android:name\\s*=\\s*\"([^\"]+)\"").matcher(blocks[i]);
			if (nameM.find()) {
				Map<String, Object> ep = new LinkedHashMap<>();
				ep.put("kind", "provider");
				ep.put("className", nameM.group(1));
				ep.put("source", "manifest");
				entrypoints.add(ep);
			}
		}

		// Activity aliases
		blocks = xml.split("<activity-alias");
		for (int i = 1; i < blocks.length; i++) {
			Matcher nameM = Pattern.compile("android:name\\s*=\\s*\"([^\"]+)\"").matcher(blocks[i]);
			Matcher targetM = Pattern.compile("android:targetActivity\\s*=\\s*\"([^\"]+)\"").matcher(blocks[i]);
			if (nameM.find()) {
				Map<String, Object> ep = new LinkedHashMap<>();
				ep.put("kind", "activity-alias");
				ep.put("className", nameM.group(1));
				if (targetM.find()) {
					ep.put("targetActivity", targetM.group(1));
				}
				ep.put("source", "manifest");
				entrypoints.add(ep);
			}
		}
	}

	@Override
	protected String getDaemonCommandName() {
		return "entrypoint-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("limit", limit);
		return args;
	}
}
