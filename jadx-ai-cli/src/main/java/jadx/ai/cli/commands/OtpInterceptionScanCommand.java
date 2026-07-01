package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * OTP / 2FA interception-risk scanner — MASVS MSTG-AUTH-6 / MSTG-PLATFORM.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from the individual channel scanners ({@code sms-scan},
 * {@code notification-listener-scan}, {@code accessibility-scan}, {@code clipboard-scan}).
 * This scanner is <b>OTP-specific</b>: it looks for patterns that specifically target one-time
 * passwords / verification codes across ALL channels, and cross-references them to flag classes
 * that intercept OTPs from multiple channels simultaneously (a clear spyware indicator).
 *
 * <p>The individual scanners detect the channel capabilities generically; this scanner answers
 * the specific question: "can this app intercept my 2FA code?"
 *
 * <p>Categories (first-match-wins per line):
 * <ul>
 *   <li>{@code sms_otp} — SMS OTP interception: {@code getMessageBody()} after
 *       {@code SMS_RECEIVED} + OTP-pattern regex in the same class (code/verify/pin/otp)</li>
 *   <li>{@code notification_otp} — Notification OTP interception: NotificationListenerService
 *       that extracts text from notifications + OTP-pattern keywords</li>
 *   <li>{@code accessibility_otp} — Accessibility OTP interception: AccessibilityService
 *       that reads node text + OTP-pattern keywords</li>
 *   <li>{@code clipboard_otp} — Clipboard OTP interception: ClipboardManager.OnPrimaryClipChangedListener
 *       + OTP-pattern keywords</li>
 *   <li>{@code multi_channel_otp} — Class that intercepts OTPs from 2+ channels simultaneously
 *       (high-confidence spyware indicator)</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, otpChannels, multiChannelClasses, truncated}}.
 */
@Command(name = "otp-interception-scan",
		description = "Detect OTP/2FA interception risk across all channels (MASVS MSTG-AUTH-6): SMS OTP body extraction, notification OTP reading, accessibility OTP reading, clipboard OTP reading, and multi-channel OTP interception (spyware indicator). OTP-specific cross of sms-scan/notification-listener-scan/accessibility-scan/clipboard-scan")
public class OtpInterceptionScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes that touch any OTP-interception-capable channel. */
	private static final Pattern OTP_MARKER = Pattern.compile(
			"SMS_RECEIVED|getMessageBody|NotificationListenerService|AccessibilityService|"
					+ "OnPrimaryClipChangedListener|ClipboardManager|otp|OTP|verification.code|verify.code");

	// Channel detection patterns
	private static final Pattern SMS_RECEIVED = Pattern.compile("SMS_RECEIVED|createFromPdu");
	private static final Pattern SMS_BODY = Pattern.compile("getMessageBody|getMessageBodyAs");
	private static final Pattern NOTIFICATION_LISTENER = Pattern.compile("NotificationListenerService");
	private static final Pattern NOTIFICATION_TEXT = Pattern.compile(
			"getText\\s*\\(|extras\\.getCharSequence|extras\\.getString\\s*\\(\"android.text\"|"
					+ "Notification\\.EXTRA_TEXT");
	private static final Pattern ACCESSIBILITY_SERVICE = Pattern.compile("AccessibilityService");
	private static final Pattern ACCESSIBILITY_TEXT = Pattern.compile(
			"getText\\s*\\(|getContentDescription|performAction|nodeInfo");
	private static final Pattern CLIPBOARD_LISTENER = Pattern.compile(
			"OnPrimaryClipChangedListener|addPrimaryClipChangedListener|ClipboardManager");
	private static final Pattern CLIPBOARD_TEXT = Pattern.compile(
			"getClipData|getItemAt|getText\\s*\\(|coerceToText");

	/** OTP-pattern keywords in code (case-insensitive via inline (?i)). */
	private static final Pattern OTP_KEYWORD = Pattern.compile(
			"(?i)(otp|one\\.?time|verification.?code|verify.?code|auth.?code|pin.?code|"
					+ "confirm.?code|security.?code|login.?code|2fa|two.?factor)");

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
		TreeSet<String> otpChannels = new TreeSet<>();
		int multiChannelClasses = 0;

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
			if (code == null || code.isEmpty() || !OTP_MARKER.matcher(code).find()) {
				continue;
			}

			// Channel detection at class level
			boolean hasSmsChannel = SMS_RECEIVED.matcher(code).find() && SMS_BODY.matcher(code).find();
			boolean hasNotificationChannel = NOTIFICATION_LISTENER.matcher(code).find()
					&& NOTIFICATION_TEXT.matcher(code).find();
			boolean hasAccessibilityChannel = ACCESSIBILITY_SERVICE.matcher(code).find()
					&& ACCESSIBILITY_TEXT.matcher(code).find();
			boolean hasClipboardChannel = CLIPBOARD_LISTENER.matcher(code).find()
					&& CLIPBOARD_TEXT.matcher(code).find();
			boolean classHasOtpKeyword = OTP_KEYWORD.matcher(code).find();

			// Per-channel findings
			if (hasSmsChannel && classHasOtpKeyword) {
				otpChannels.add("sms");
				findings.add(finding("sms_otp", "high", fullName, 0,
						"Class intercepts SMS messages and contains OTP/verification-code keywords — "
								+ "likely reads 2FA codes from incoming SMS"));
				highSeverityCount++;
			}
			if (hasNotificationChannel && classHasOtpKeyword) {
				otpChannels.add("notification");
				findings.add(finding("notification_otp", "high", fullName, 0,
						"NotificationListenerService reads notification text and class contains OTP keywords — "
								+ "likely reads 2FA codes from notifications"));
				highSeverityCount++;
			}
			if (hasAccessibilityChannel && classHasOtpKeyword) {
				otpChannels.add("accessibility");
				findings.add(finding("accessibility_otp", "high", fullName, 0,
						"AccessibilityService reads UI text and class contains OTP keywords — "
								+ "likely reads 2FA codes from other apps' screens"));
				highSeverityCount++;
			}
			if (hasClipboardChannel && classHasOtpKeyword) {
				otpChannels.add("clipboard");
				findings.add(finding("clipboard_otp", "medium", fullName, 0,
						"ClipboardManager listener reads clipboard and class contains OTP keywords — "
								+ "may intercept 2FA codes copied to clipboard"));
			}

			// Multi-channel: class intercepts OTPs from 2+ channels
			int channelCount = 0;
			if (hasSmsChannel) channelCount++;
			if (hasNotificationChannel) channelCount++;
			if (hasAccessibilityChannel) channelCount++;
			if (hasClipboardChannel) channelCount++;
			if (channelCount >= 2 && classHasOtpKeyword) {
				multiChannelClasses++;
				findings.add(finding("multi_channel_otp", "high", fullName, 0,
						"Class can intercept OTPs from " + channelCount + " channels simultaneously — "
								+ "high-confidence spyware indicator (targets 2FA regardless of delivery method)"));
				highSeverityCount++;
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("otpChannels", new ArrayList<>(otpChannels));
		data.put("multiChannelClasses", multiChannelClasses);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String kind, String severity, String className, int line, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("className", className);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "otp-interception-scan";
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
