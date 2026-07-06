package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.ManifestUtil;
import jadx.api.JadxDecompiler;

/**
 * Unsafe exported-component scanner — MASVS MSTG-PLATFORM.
 * Native: reads jadx's decoded manifest, no external tool.
 *
 * <p>Distinct from {@code manifest-audit} (comprehensive manifest inventory) and
 * {@code exported-provider-scan} (only ContentProviders). This scanner focuses on
 * <b>exported components that lack permission protection</b>: any app on the device can
 * invoke them. It also flags components that are implicitly exported (intent-filter present,
 * no explicit {@code android:exported} attribute — defaults to true on API &lt; 31).
 *
 * <p>Categories:
 * <ul>
 *   <li>{@code exported_no_permission} — Exported component with no
 *       {@code android:permission} attribute — any app can invoke it</li>
 *   <li>{@code implicitly_exported} — Component with intent-filter but no explicit
 *       {@code android:exported} attribute — implicitly exported on API &lt; 31</li>
 *   <li>{@code exported_with_permission} — Exported component with permission protection
 *       (inventory, not a vulnerability)</li>
 * </ul>
 *
 * <p>Inventory shape (no severity — an exported component is a surface; the risk depends on
 * what the component does with the input and whether the permission is enforced).
 *
 * Returns {@code {findings:[{category,component,componentType,exported,permission,detail}],
 * count, exportedWithoutPermission, exportedWithPermission, implicitlyExported, truncated}}.
 */
@Command(name = "unsafe-export-scan",
		description = "Detect exported components lacking permission protection (MASVS MSTG-PLATFORM): exported Activity/Service/BroadcastReceiver/ContentProvider without android:permission, implicitly exported components (intent-filter without explicit exported attr). Distinct from manifest-audit and exported-provider-scan")
public class UnsafeExportScanCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern[] COMPONENT_PATTERNS = {
		Pattern.compile("<(activity|activity-alias)\\b([^>]*?)/>", Pattern.DOTALL),
		Pattern.compile("<(activity|activity-alias)\\b([^>]*?)>(.*?)</\\1>", Pattern.DOTALL),
		Pattern.compile("<service\\b([^>]*?)/>", Pattern.DOTALL),
		Pattern.compile("<service\\b([^>]*?)>(.*?)</service>", Pattern.DOTALL),
		Pattern.compile("<receiver\\b([^>]*?)/>", Pattern.DOTALL),
		Pattern.compile("<receiver\\b([^>]*?)>(.*?)</receiver>", Pattern.DOTALL),
		Pattern.compile("<provider\\b([^>]*?)/>", Pattern.DOTALL),
		Pattern.compile("<provider\\b([^>]*?)>(.*?)</provider>", Pattern.DOTALL),
	};

	private static final Pattern ATTR_NAME = Pattern.compile(
			Pattern.quote("android:name") + "\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern ATTR_EXPORTED = Pattern.compile(
			Pattern.quote("android:exported") + "\\s*=\\s*\"(true|false)\"");
	private static final Pattern ATTR_PERMISSION = Pattern.compile(
			Pattern.quote("android:permission") + "\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern ATTR_READ_PERMISSION = Pattern.compile(
			Pattern.quote("android:readPermission") + "\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern ATTR_WRITE_PERMISSION = Pattern.compile(
			Pattern.quote("android:writePermission") + "\\s*=\\s*\"([^\"]+)\"");
	// Match the opening <intent-filter ...> tag WITH OR WITHOUT attributes. A plain "<intent-filter>"
	// contains() check silently misses the very common attributed forms — <intent-filter
	// android:autoVerify="true"> (every App Links / deep-link handler) and <intent-filter
	// android:priority="..."> — which would make an implicitly-exported component read as un-exported.
	private static final Pattern INTENT_FILTER = Pattern.compile("<intent-filter[\\s>]");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();
		int exportedWithoutPermission = 0;
		int exportedWithPermission = 0;
		int implicitlyExported = 0;

		String manifest = ManifestUtil.loadManifestText(decompiler);
		if (manifest == null) {
			return JsonOutput.error("ManifestNotFound",
					"No AndroidManifest.xml found; unsafe-export-scan requires an APK input");
		}

		for (Pattern p : COMPONENT_PATTERNS) {
			Matcher m = p.matcher(manifest);
			while (m.find() && findings.size() < limit) {
				String tagType;
				String attrs;
				String body;

				// Determine tag type and extract attrs/body based on pattern
				if (m.group(1) != null && (m.group(1).equals("activity") || m.group(1).equals("activity-alias"))) {
					tagType = m.group(1);
					attrs = m.group(2);
					body = m.groupCount() >= 3 ? m.group(3) : "";
				} else if (m.pattern().pattern().startsWith("<service")) {
					tagType = "service";
					attrs = m.group(1);
					body = m.groupCount() >= 2 ? m.group(2) : "";
				} else if (m.pattern().pattern().startsWith("<receiver")) {
					tagType = "receiver";
					attrs = m.group(1);
					body = m.groupCount() >= 2 ? m.group(2) : "";
				} else if (m.pattern().pattern().startsWith("<provider")) {
					tagType = "provider";
					attrs = m.group(1);
					body = m.groupCount() >= 2 ? m.group(2) : "";
				} else {
					continue;
				}

				String componentName = attr(attrs, ATTR_NAME);
				if (componentName == null) {
					continue;
				}

				// Determine exported status
				String exportedStr = attr(attrs, ATTR_EXPORTED);
				boolean hasIntentFilter = hasIntentFilter(body);
				boolean exported;
				boolean explicitExported = exportedStr != null;

				if (explicitExported) {
					exported = "true".equals(exportedStr);
				} else {
					// Implicit: intent-filter present → exported on API < 31
					exported = hasIntentFilter;
				}

				if (!exported) {
					continue;
				}

				// Check for permission protection
				String permission = attr(attrs, ATTR_PERMISSION);
				String readPermission = attr(attrs, ATTR_READ_PERMISSION);
				String writePermission = attr(attrs, ATTR_WRITE_PERMISSION);
				boolean hasPermission = permission != null || readPermission != null || writePermission != null;

				String permStr = permission != null ? permission
						: (readPermission != null ? readPermission + "/r" + (writePermission != null ? "+" + writePermission + "/w" : "")
						: (writePermission != null ? writePermission + "/w" : null));

				if (!explicitExported && hasIntentFilter) {
					implicitlyExported++;
					findings.add(finding("implicitly_exported", componentName, tagType, true, permStr,
							"Component has intent-filter but no explicit android:exported attribute — "
									+ "implicitly exported on API < 31; any app can invoke it"));
				} else if (!hasPermission) {
					exportedWithoutPermission++;
					findings.add(finding("exported_no_permission", componentName, tagType, true, null,
							"Exported " + tagType + " without android:permission — any app on the device can invoke it; "
									+ "add a signature|privileged permission or set exported=false"));
				} else {
					exportedWithPermission++;
					findings.add(finding("exported_with_permission", componentName, tagType, true, permStr,
							"Exported " + tagType + " with permission protection (" + permStr + ")"));
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("exportedWithoutPermission", exportedWithoutPermission);
		data.put("exportedWithPermission", exportedWithPermission);
		data.put("implicitlyExported", implicitlyExported);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static String attr(String text, Pattern p) {
		Matcher m = p.matcher(text);
		return m.find() ? m.group(1) : null;
	}

	/**
	 * True if the component body declares an {@code <intent-filter>}, with or without attributes.
	 * Package-private so a test can assert the attributed forms ({@code android:autoVerify},
	 * {@code android:priority}) that a bare {@code "<intent-filter>"} check silently drops.
	 */
	static boolean hasIntentFilter(String body) {
		return INTENT_FILTER.matcher(body).find();
	}

	private static Map<String, Object> finding(String category, String component, String componentType,
			boolean exported, String permission, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("category", category);
		f.put("component", component);
		f.put("componentType", componentType);
		f.put("exported", exported);
		f.put("permission", permission);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "unsafe-export-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("limit", limit);
		return args;
	}
}
