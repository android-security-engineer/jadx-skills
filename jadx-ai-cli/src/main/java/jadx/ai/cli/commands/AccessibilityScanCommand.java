package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Scans for AccessibilityService abuse — MASVS MSTG-PLATFORM. Native: reads jadx's parsed model,
 * no external tool.
 *
 * <p>{@code AccessibilityService} is the single most abused Android capability in banking trojans
 * (Anatsa, Cerberus, SharkBot, Xenomorph, …). With the user tricked into granting it, the service
 * can <em>read every word on screen</em> (including other apps' password fields) and
 * <em>synthesise taps and gestures</em> — together that is a screen-reading keylogger plus a remote
 * UI robot that auto-grants its own permissions, dismisses warnings, and drives fund transfers. The
 * dangerous shape is a class that BOTH scrapes window content AND automates the UI; this scanner
 * surfaces each half and the summary booleans so the pairing is obvious. Pairs with
 * {@code tapjacking-scan} (overlays) — overlay + accessibility is the full trojan kit.
 * <ul>
 *   <li><b>screen_scrape</b> (high) — {@code getRootInActiveWindow} /
 *       {@code findAccessibilityNodeInfosByText|ByViewId}: reads arbitrary on-screen content of
 *       any app, the keylogging / overlay-targeting primitive.</li>
 *   <li><b>keylogger</b> (high) — handles {@code TYPE_VIEW_TEXT_CHANGED}: captures keystrokes /
 *       field edits across apps.</li>
 *   <li><b>ui_automation</b> (high) — {@code performGlobalAction} / {@code dispatchGesture} /
 *       {@code GLOBAL_ACTION_*}: synthesises back/home/recents, taps and gestures — auto-grants
 *       permissions, dismisses dialogs, drives transfers.</li>
 *   <li><b>node_action</b> (medium) — {@code AccessibilityNodeInfo.performAction} /
 *       {@code ACTION_CLICK|SET_TEXT|PASTE}: programmatically clicks/fills other apps' widgets.</li>
 *   <li><b>window_content_capability</b> (info) — declares
 *       {@code canRetrieveWindowContent} / {@code flagRetrieveInteractiveWindows}.</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * readsScreen, automatesUi, truncated}}.
 */
@Command(name = "accessibility-scan",
		description = "Scan for AccessibilityService abuse (MASVS MSTG-PLATFORM): screen scraping, cross-app keylogging (TYPE_VIEW_TEXT_CHANGED), UI automation (performGlobalAction/dispatchGesture) — the banking-trojan kit")
public class AccessibilityScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Class-level gate: only classes that touch the accessibility framework. */
	private static final Pattern ACCESSIBILITY_MARKER = Pattern.compile(
			"AccessibilityService|onAccessibilityEvent|AccessibilityNodeInfo|"
					+ "BIND_ACCESSIBILITY_SERVICE|android\\.accessibilityservice|AccessibilityEvent");

	private static final class Rule {
		final Pattern pattern;
		final String kind;
		final String severity;
		final String detail;

		Rule(String regex, String kind, String severity, String detail) {
			this.pattern = Pattern.compile(regex);
			this.kind = kind;
			this.severity = severity;
			this.detail = detail;
		}
	}

	/** High-severity first so the first matching rule on a line wins. */
	private static final List<Rule> RULES = List.of(
			new Rule("getRootInActiveWindow|findAccessibilityNodeInfosByText|findAccessibilityNodeInfosByViewId|getWindows\\s*\\(",
					"screen_scrape", "high",
					"Reads arbitrary on-screen content of any app (getRootInActiveWindow / findAccessibilityNodeInfos...) — the keylogging / overlay-targeting primitive abused by banking trojans"),
			new Rule("TYPE_VIEW_TEXT_CHANGED",
					"keylogger", "high",
					"Handles TYPE_VIEW_TEXT_CHANGED — captures keystrokes / field edits across apps via the accessibility event stream"),
			new Rule("performGlobalAction\\s*\\(|dispatchGesture\\s*\\(|GLOBAL_ACTION_",
					"ui_automation", "high",
					"Synthesises UI actions (performGlobalAction / dispatchGesture / GLOBAL_ACTION_*) — auto-grants permissions, dismisses warnings, drives taps/gestures programmatically"),
			new Rule("\\.performAction\\s*\\(|ACTION_CLICK|ACTION_SET_TEXT|ACTION_PASTE",
					"node_action", "medium",
					"Programmatically actions another app's widget (AccessibilityNodeInfo.performAction / ACTION_CLICK|SET_TEXT|PASTE) — clicks/fills UI without user input"),
			new Rule("canRetrieveWindowContent|flagRetrieveInteractiveWindows|FLAG_RETRIEVE_INTERACTIVE_WINDOWS",
					"window_content_capability", "info",
					"Requests window-content retrieval capability (canRetrieveWindowContent / flagRetrieveInteractiveWindows) — broad read access to other apps' UI"));

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();
		int highSeverityCount = 0;
		boolean readsScreen = false;
		boolean automatesUi = false;

		for (JavaClass cls : decompiler.getClasses()) {
			if (findings.size() >= limit) {
				break;
			}
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
			if (code == null || code.isEmpty() || !ACCESSIBILITY_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!r.pattern.matcher(line).find()) {
						continue;
					}
					findings.add(finding(fullName, i + 1, r.kind, r.severity, r.detail));
					if ("high".equals(r.severity)) {
						highSeverityCount++;
					}
					if ("screen_scrape".equals(r.kind) || "keylogger".equals(r.kind)) {
						readsScreen = true;
					} else if ("ui_automation".equals(r.kind) || "node_action".equals(r.kind)) {
						automatesUi = true;
					}
					break; // one finding per line — first (highest-severity) rule wins
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("readsScreen", readsScreen);
		data.put("automatesUi", automatesUi);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String cls, int line, String kind, String severity, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("className", cls);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "accessibility-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
