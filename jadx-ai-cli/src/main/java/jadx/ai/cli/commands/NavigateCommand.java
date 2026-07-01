package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

@Command(name = "navigate", description = "Navigate to APK entry points and key components")
public class NavigateCommand extends AbstractCommand {

	@Option(names = {"-t", "--type"}, description = "Navigation type: main-activity, application, manifest, entry-points", defaultValue = "entry-points")
	protected String navType;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		switch (navType) {
			case "main-activity":
				return findMainActivity(decompiler);
			case "application":
				return findApplicationClass(decompiler);
			case "manifest":
				return findManifest(decompiler);
			case "entry-points":
				return findAllEntryPoints(decompiler);
			default:
				return JsonOutput.error("InvalidType", "Unknown navigation type: " + navType);
		}
	}

	private Object findMainActivity(JadxDecompiler decompiler) throws Exception {
		String manifest = loadManifestContent(decompiler);
		if (manifest == null) {
			return JsonOutput.error("ManifestNotFound", "AndroidManifest.xml not found in resources");
		}
		String activity = extractByPattern(manifest,
				"<activity[^>]*android:name=\"([^\"]+)\"[^>]*>.*?<action[^>]*android:name=\"android.intent.action.MAIN\".*?</activity>",
				true);
		if (activity == null) {
			activity = extractByPattern(manifest,
					"<activity[^>]*>.*?<action[^>]*android:name=\"android.intent.action.MAIN\".*?</activity>",
					false);
			if (activity != null) {
				activity = extractByPattern(activity, "android:name=\"([^\"]+)\"", true);
			}
		}
		if (activity == null) {
			return JsonOutput.error("NotFound", "Main activity not found in manifest");
		}
		Map<String, Object> result = new HashMap<>();
		result.put("mainActivity", activity);
		return JsonOutput.ok(result);
	}

	private Object findApplicationClass(JadxDecompiler decompiler) throws Exception {
		String manifest = loadManifestContent(decompiler);
		if (manifest == null) {
			return JsonOutput.error("ManifestNotFound", "AndroidManifest.xml not found in resources");
		}
		String appClass = extractByPattern(manifest,
				"<application[^>]*android:name=\"([^\"]+)\"", true);
		if (appClass == null) {
			return JsonOutput.error("NotFound", "Application class not found in manifest");
		}
		Map<String, Object> result = new HashMap<>();
		result.put("applicationClass", appClass);
		return JsonOutput.ok(result);
	}

	private Object findManifest(JadxDecompiler decompiler) throws Exception {
		String manifest = loadManifestContent(decompiler);
		if (manifest == null) {
			return JsonOutput.error("ManifestNotFound", "AndroidManifest.xml not found in resources");
		}
		Map<String, Object> result = new HashMap<>();
		result.put("manifest", manifest);
		return JsonOutput.ok(result);
	}

	private Object findAllEntryPoints(JadxDecompiler decompiler) throws Exception {
		String manifest = loadManifestContent(decompiler);
		Map<String, Object> result = new HashMap<>();
		if (manifest == null) {
			result.put("error", "AndroidManifest.xml not found");
			return JsonOutput.ok(result);
		}

		List<String> activities = extractAllByPattern(manifest,
				"<activity[^>]*android:name=\"([^\"]+)\"");
		List<String> services = extractAllByPattern(manifest,
				"<service[^>]*android:name=\"([^\"]+)\"");
		List<String> receivers = extractAllByPattern(manifest,
				"<receiver[^>]*android:name=\"([^\"]+)\"");
		List<String> providers = extractAllByPattern(manifest,
				"<provider[^>]*android:name=\"([^\"]+)\"");

		String appClass = extractByPattern(manifest,
				"<application[^>]*android:name=\"([^\"]+)\"", true);
		String mainActivity = extractByPattern(manifest,
				"<activity[^>]*android:name=\"([^\"]+)\"[^>]*>.*?<action[^>]*android:name=\"android.intent.action.MAIN\".*?</activity>",
				true);

		result.put("mainActivity", mainActivity);
		result.put("applicationClass", appClass);
		result.put("activities", activities);
		result.put("services", services);
		result.put("receivers", receivers);
		result.put("providers", providers);
		result.put("totalEntryPoints", activities.size() + services.size() + receivers.size() + providers.size());
		return JsonOutput.ok(result);
	}

	private String loadManifestContent(JadxDecompiler decompiler) throws Exception {
		return jadx.ai.cli.util.ManifestUtil.loadManifestText(decompiler);
	}

	private String extractByPattern(String text, String regex, boolean extractGroup) {
		java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex, java.util.regex.Pattern.DOTALL);
		java.util.regex.Matcher matcher = pattern.matcher(text);
		if (matcher.find()) {
			return extractGroup && matcher.groupCount() >= 1 ? matcher.group(1) : matcher.group(0);
		}
		return null;
	}

	private List<String> extractAllByPattern(String text, String regex) {
		List<String> results = new ArrayList<>();
		java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex, java.util.regex.Pattern.DOTALL);
		java.util.regex.Matcher matcher = pattern.matcher(text);
		while (matcher.find()) {
			if (matcher.groupCount() >= 1) {
				results.add(matcher.group(1));
			}
		}
		return results;
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("type", navType);
		return args;
	}
}
