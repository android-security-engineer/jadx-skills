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
 * Scans for {@code NotificationListenerService} abuse — MASVS MSTG-PLATFORM. Native: reads jadx's
 * parsed model, no external tool.
 *
 * <p>{@code NotificationListenerService} (gated by {@code BIND_NOTIFICATION_LISTENER_SERVICE} and a
 * user toggle, like accessibility) lets an app read <em>every notification from every app</em>.
 * That is the OTP/2FA theft primitive in modern banking trojans: the bank texts a one-time code,
 * Android posts it as a notification, and the trojan's listener reads the body and exfiltrates it —
 * defeating SMS-based 2FA without the {@code READ_SMS} permission. It can also silently dismiss
 * fraud-alert notifications. This scanner is scoped to listener classes and surfaces the read,
 * the body-extraction, and the dismiss capabilities, plus an explicit OTP-keyword hit. Pairs with
 * {@code accessibility-scan} — accessibility + notification-listener is the full credential-theft
 * kit.
 * <ul>
 *   <li><b>notification_read</b> (high) — {@code onNotificationPosted} /
 *       {@code getActiveNotifications}: reads all apps' notifications.</li>
 *   <li><b>notification_text_extract</b> (high) — pulls the notification body
 *       ({@code EXTRA_TEXT}/{@code EXTRA_TITLE}/{@code EXTRA_BIG_TEXT}/{@code "android.text"}) — the
 *       OTP/2FA exfiltration step.</li>
 *   <li><b>otp_targeting</b> (high) — an OTP / one-time-code / 2FA keyword in a listener class,
 *       evidence the read is aimed at second factors.</li>
 *   <li><b>notification_dismiss</b> (medium) — {@code cancelNotification} /
 *       {@code cancelAllNotifications}: can hide fraud-alert notifications from the user.</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * readsNotifications, extractsText, truncated}}.
 */
@Command(name = "notification-listener-scan",
		description = "Scan for NotificationListenerService abuse (MASVS MSTG-PLATFORM): reads all apps' notifications (OTP/2FA theft), extracts message body (EXTRA_TEXT), targets OTP keywords, dismisses fraud alerts. Pairs with accessibility-scan")
public class NotificationListenerScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Class-level gate: only notification-listener implementations. */
	private static final Pattern LISTENER_MARKER = Pattern.compile(
			"NotificationListenerService|onNotificationPosted|BIND_NOTIFICATION_LISTENER_SERVICE|"
					+ "getActiveNotifications|StatusBarNotification");

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
			new Rule("onNotificationPosted\\s*\\(|getActiveNotifications\\s*\\(",
					"notification_read", "high",
					"Reads notifications from all apps (onNotificationPosted / getActiveNotifications) — the OTP/2FA theft primitive; can capture one-time codes the bank posts as notifications without holding READ_SMS"),
			new Rule("EXTRA_TEXT|EXTRA_TITLE|EXTRA_BIG_TEXT|EXTRA_TEXT_LINES|EXTRA_SUB_TEXT|"
					+ "\"android\\.text\"|\"android\\.title\"|\"android\\.bigText\"",
					"notification_text_extract", "high",
					"Extracts notification body/title (EXTRA_TEXT / \"android.text\") — pulls the message content, the OTP/2FA exfiltration step"),
			new Rule("(?i)\\b(otp|one[-_ ]?time[-_ ]?(code|password)|verification[-_ ]?code|2fa|two[-_ ]?factor|auth[-_ ]?code|passcode)\\b",
					"otp_targeting", "high",
					"OTP / one-time-code / 2FA keyword in a notification-listener class — evidence the notification read is aimed at second factors (credential theft)"),
			new Rule("cancelNotification\\s*\\(|cancelAllNotifications\\s*\\(",
					"notification_dismiss", "medium",
					"Dismisses notifications (cancelNotification / cancelAllNotifications) — can hide fraud-alert / security notifications from the user"));

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
		boolean readsNotifications = false;
		boolean extractsText = false;

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
			if (code == null || code.isEmpty() || !LISTENER_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			boolean reportedOtp = false;
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!r.pattern.matcher(line).find()) {
						continue;
					}
					if ("otp_targeting".equals(r.kind)) {
						if (reportedOtp) {
							break; // one OTP-keyword finding per class to avoid noise
						}
						reportedOtp = true;
					}
					findings.add(finding(fullName, i + 1, r.kind, r.severity, r.detail));
					if ("high".equals(r.severity)) {
						highSeverityCount++;
					}
					if ("notification_read".equals(r.kind)) {
						readsNotifications = true;
					} else if ("notification_text_extract".equals(r.kind)) {
						extractsText = true;
					}
					break; // one finding per line — first (highest-severity) rule wins
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("readsNotifications", readsNotifications);
		data.put("extractsText", extractsText);
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
		return "notification-listener-scan";
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
