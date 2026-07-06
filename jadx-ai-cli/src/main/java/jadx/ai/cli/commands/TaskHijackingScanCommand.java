package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
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
 * Detects susceptibility to <b>task hijacking</b> — the StrandHogg (1.0) class of attacks
 * (MASVS MSTG-PLATFORM). Native: parses jadx's decoded {@code AndroidManifest.xml}, no external tool.
 *
 * <p>Distinct from every other manifest scanner here: {@code manifest-audit} flags exported
 * components, {@code deep-link-audit} parses intent-filters for VIEW links, {@code intent-scan}
 * looks at code-level IPC. None reason about <em>task control</em>. StrandHogg abuses Android's task
 * model: a malicious app declares a {@code taskAffinity} matching (or empty toward) the victim and a
 * {@code launchMode} of {@code singleTask}/{@code singleInstance}, so when the user launches the
 * victim the attacker's phishing/overlay activity is shown <em>inside the victim's task</em>. An app
 * is <b>susceptible</b> when its launcher/exported activities keep the default task affinity (= the
 * package name, non-empty) instead of opting out with {@code android:taskAffinity=""}, and don't
 * isolate themselves with {@code launchMode="singleInstance"}. {@code allowTaskReparenting="true"}
 * compounds it by letting activities migrate between tasks.
 *
 * <p>The robust mitigation is {@code android:taskAffinity=""} on the {@code <application>} (or every
 * launchable activity); this scanner recognises that and reports {@code appLevelMitigated=true}.
 *
 * Returns {@code {findings:[{kind,severity,activity,detail}], count, mediumSeverityCount,
 * appLevelMitigated, launcherVulnerable, usesTaskReparenting, truncated}}.
 */
@Command(name = "task-hijacking-scan",
		description = "Detect StrandHogg task-hijacking susceptibility (MASVS-PLATFORM): launcher/exported activities keeping the default taskAffinity instead of android:taskAffinity=\"\", risky launchMode, allowTaskReparenting. Not covered by manifest-audit/intent-scan")
public class TaskHijackingScanCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern SELF_CLOSING =
			Pattern.compile("<(activity|activity-alias)\\b([^>]*?)/>", Pattern.DOTALL);
	private static final Pattern BLOCK =
			Pattern.compile("<(activity|activity-alias)\\b([^>]*?)>(.*?)</\\1>", Pattern.DOTALL);
	private static final Pattern LAUNCHER =
			Pattern.compile("android\\.intent\\.category\\.LAUNCHER", Pattern.DOTALL);

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		String manifest = ManifestUtil.loadManifestText(decompiler);
		if (manifest == null) {
			return JsonOutput.error("ManifestNotFound", "AndroidManifest.xml not found in resources");
		}

		// App-level opt-out: <application android:taskAffinity=""> mitigates the whole app.
		String appTag = ManifestUtil.extractFirst(manifest, "(<application\\b[^>]*>)");
		boolean appLevelMitigated = appTag != null && "".equals(attr(appTag, "android:taskAffinity"));

		List<Map<String, Object>> findings = new ArrayList<>();
		boolean launcherVulnerable = false;
		boolean usesTaskReparenting = false;
		int mediumSeverityCount = 0;

		List<String[]> activities = new ArrayList<>(); // {attrs, body}
		Matcher sc = SELF_CLOSING.matcher(manifest);
		while (sc.find()) {
			activities.add(new String[] { sc.group(2), "" });
		}
		Matcher bl = BLOCK.matcher(manifest);
		while (bl.find()) {
			activities.add(new String[] { bl.group(2), bl.group(3) });
		}

		for (String[] act : activities) {
			if (findings.size() >= limit) {
				break;
			}
			String attrs = act[0];
			String body = act[1];
			String name = attr(attrs, "android:name");
			String affinity = attr(attrs, "android:taskAffinity"); // null = default (package name)
			String launchMode = attr(attrs, "android:launchMode"); // null = standard
			boolean reparent = "true".equalsIgnoreCase(attr(attrs, "android:allowTaskReparenting"));
			boolean exportedAttr = "true".equalsIgnoreCase(attr(attrs, "android:exported"));
			boolean isLauncher = LAUNCHER.matcher(body).find();
			boolean exposed = isLauncher || exportedAttr;

			// Empty affinity ("") opts out of task sharing — the per-activity mitigation.
			boolean defaultAffinity = affinity == null || !affinity.isEmpty();
			boolean isolated = "singleInstance".equalsIgnoreCase(launchMode);

			if (reparent) {
				usesTaskReparenting = true;
				findings.add(finding("task_reparenting", "medium", name,
						"android:allowTaskReparenting=\"true\" lets this activity migrate into another task — aids task hijacking"));
				mediumSeverityCount++;
				continue;
			}

			if (!appLevelMitigated && exposed && defaultAffinity && !isolated) {
				if ("singleTask".equalsIgnoreCase(launchMode)) {
					findings.add(finding("strandhogg_singletask", "medium", name,
							"launchMode=\"singleTask\" with the default taskAffinity on an exposed activity — the classic StrandHogg precondition; set android:taskAffinity=\"\""));
				} else {
					findings.add(finding("task_hijacking_affinity", "medium", name,
							"Exposed activity keeps the default taskAffinity (no android:taskAffinity=\"\") and is not launchMode=\"singleInstance\" — susceptible to StrandHogg task injection"));
				}
				mediumSeverityCount++;
				if (isLauncher) {
					launcherVulnerable = true;
				}
			}
		}

		if (appLevelMitigated && findings.isEmpty()) {
			findings.add(finding("task_affinity_optout", "info", "<application>",
					"android:taskAffinity=\"\" set at application level — opted out of task sharing (StrandHogg mitigation)"));
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("mediumSeverityCount", mediumSeverityCount);
		data.put("appLevelMitigated", appLevelMitigated);
		data.put("launcherVulnerable", launcherVulnerable);
		data.put("usesTaskReparenting", usesTaskReparenting);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String kind, String severity, String activity, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("activity", activity);
		f.put("detail", detail);
		return f;
	}

	/** Extract {@code name="value"} from an element's attribute string, or null. */
	private static String attr(String attrs, String name) {
		Matcher m = Pattern.compile(Pattern.quote(name) + "\\s*=\\s*\"([^\"]*)\"").matcher(attrs);
		return m.find() ? m.group(1) : null;
	}

	@Override
	protected String getDaemonCommandName() {
		return "task-hijacking-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("limit", limit);
		return args;
	}
}
