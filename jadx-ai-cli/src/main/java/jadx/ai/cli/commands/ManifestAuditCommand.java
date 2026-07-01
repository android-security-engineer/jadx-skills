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
import jadx.ai.cli.util.ManifestUtil;
import jadx.api.JadxDecompiler;

/**
 * Static security audit of {@code AndroidManifest.xml} — the MobSF-style manifest checks, absorbed
 * natively. Native capability: reads jadx's decoded manifest resource, no external tool. Flags:
 * <ul>
 *   <li>exported components ({@code activity}/{@code service}/{@code receiver}/{@code provider})
 *       reachable without a guarding {@code android:permission} (explicit {@code exported="true"} or
 *       an intent-filter with no {@code exported} attribute, which is implicitly exported pre-S)</li>
 *   <li>application flags: {@code debuggable}, {@code allowBackup}, {@code usesCleartextTraffic}</li>
 *   <li>absence of a {@code networkSecurityConfig}</li>
 * </ul>
 */
@Command(name = "manifest-audit", description = "Audit AndroidManifest.xml for exported components and risky application flags")
public class ManifestAuditCommand extends AbstractCommand {

	@Option(names = { "--exported-only" }, description = "Only report exported components, skip app-flag checks")
	protected boolean exportedOnly;

	private static final Pattern SELF_CLOSING =
			Pattern.compile("<(activity|activity-alias|service|receiver|provider)\\b([^>]*?)/>", Pattern.DOTALL);
	private static final Pattern BLOCK =
			Pattern.compile("<(activity|activity-alias|service|receiver|provider)\\b([^>]*?)>(.*?)</\\1>", Pattern.DOTALL);

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("exportedOnly")) {
			this.exportedOnly = Boolean.TRUE.equals(args.get("exportedOnly"));
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		String manifest = ManifestUtil.loadManifestText(decompiler);
		if (manifest == null) {
			return JsonOutput.error("ManifestNotFound", "AndroidManifest.xml not found in resources");
		}

		List<Map<String, Object>> components = new ArrayList<>();
		// Self-closing components have no body, hence no intent-filter.
		Matcher sc = SELF_CLOSING.matcher(manifest);
		while (sc.find()) {
			components.add(analyzeComponent(sc.group(1), sc.group(2), ""));
		}
		Matcher bl = BLOCK.matcher(manifest);
		while (bl.find()) {
			components.add(analyzeComponent(bl.group(1), bl.group(2), bl.group(3)));
		}

		List<Map<String, Object>> exported = new ArrayList<>();
		List<Map<String, Object>> findings = new ArrayList<>();
		for (Map<String, Object> c : components) {
			if (Boolean.TRUE.equals(c.get("exported"))) {
				exported.add(c);
				if (Boolean.FALSE.equals(c.get("permissionGuarded"))) {
					Map<String, Object> f = new LinkedHashMap<>();
					f.put("kind", "exported_no_permission");
					f.put("severity", severityFor((String) c.get("type")));
					f.put("type", c.get("type"));
					f.put("name", c.get("name"));
					f.put("detail", c.get("type") + " is exported without a permission guard"
							+ (Boolean.TRUE.equals(c.get("implicitlyExported")) ? " (implicit via intent-filter)" : ""));
					findings.add(f);
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("exportedComponents", exported);
		data.put("findings", findings);
		if (!exportedOnly) {
			data.put("applicationFlags", auditAppFlags(manifest, findings));
		}
		data.put("findingCount", findings.size());
		return JsonOutput.ok(data);
	}

	private Map<String, Object> analyzeComponent(String type, String attrs, String body) {
		String name = attr(attrs, "android:name");
		String exportedAttr = attr(attrs, "android:exported");
		boolean hasIntentFilter = body.contains("<intent-filter");
		boolean permissionGuarded = attr(attrs, "android:permission") != null;

		boolean exported;
		boolean implicit = false;
		if ("true".equalsIgnoreCase(exportedAttr)) {
			exported = true;
		} else if ("false".equalsIgnoreCase(exportedAttr)) {
			exported = false;
		} else {
			// No explicit attribute: implicitly exported iff it declares an intent-filter.
			exported = hasIntentFilter;
			implicit = exported;
		}

		Map<String, Object> c = new LinkedHashMap<>();
		c.put("type", type);
		c.put("name", name);
		c.put("exported", exported);
		c.put("implicitlyExported", implicit);
		c.put("hasIntentFilter", hasIntentFilter);
		c.put("permissionGuarded", permissionGuarded);
		return c;
	}

	private Map<String, Object> auditAppFlags(String manifest, List<Map<String, Object>> findings) {
		String appTag = ManifestUtil.extractFirst(manifest, "(<application\\b[^>]*>)");
		Map<String, Object> flags = new LinkedHashMap<>();
		if (appTag == null) {
			return flags;
		}
		boolean debuggable = "true".equalsIgnoreCase(attr(appTag, "android:debuggable"));
		String backupAttr = attr(appTag, "android:allowBackup");
		boolean allowBackup = backupAttr == null || "true".equalsIgnoreCase(backupAttr); // default true
		boolean cleartext = "true".equalsIgnoreCase(attr(appTag, "android:usesCleartextTraffic"));
		boolean hasNsc = attr(appTag, "android:networkSecurityConfig") != null;

		flags.put("debuggable", debuggable);
		flags.put("allowBackup", allowBackup);
		flags.put("usesCleartextTraffic", cleartext);
		flags.put("networkSecurityConfig", hasNsc);

		if (debuggable) {
			findings.add(flagFinding("debuggable", "high", "android:debuggable=\"true\" ships a debuggable app"));
		}
		if (allowBackup) {
			findings.add(flagFinding("allow_backup", "medium",
					"android:allowBackup is enabled — app data can be extracted via adb backup"));
		}
		if (cleartext) {
			findings.add(flagFinding("cleartext_traffic", "medium",
					"android:usesCleartextTraffic=\"true\" permits unencrypted HTTP"));
		}
		return flags;
	}

	private static Map<String, Object> flagFinding(String kind, String severity, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("detail", detail);
		return f;
	}

	private static String severityFor(String type) {
		if ("provider".equals(type)) {
			return "high";
		}
		if ("receiver".equals(type) || "service".equals(type)) {
			return "medium";
		}
		return "low";
	}

	/** Extract {@code name="value"} from an element's attribute string, or null. */
	private static String attr(String attrs, String name) {
		Matcher m = Pattern.compile(Pattern.quote(name) + "\\s*=\\s*\"([^\"]*)\"").matcher(attrs);
		return m.find() ? m.group(1) : null;
	}

	@Override
	protected String getDaemonCommandName() {
		return "manifest-audit";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new java.util.HashMap<>();
		args.put("exportedOnly", exportedOnly);
		return args;
	}
}
