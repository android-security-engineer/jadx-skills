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
 * Scans for SMS interception / abuse — MASVS MSTG-PLATFORM / MSTG-CODE. Native: reads jadx's parsed
 * model, no external tool.
 *
 * <p>SMS is the other half of OTP/2FA theft (the companion to {@code notification-listener-scan}): a
 * {@code BroadcastReceiver} on {@code SMS_RECEIVED} reads the incoming message body and exfiltrates
 * the one-time code, while {@code abortBroadcast()} (pre-default-SMS-app era) or quiet handling
 * keeps the user from seeing it. The same SMS APIs drive premium-SMS fraud
 * ({@code sendTextMessage} to short codes) and worm-style self-propagation. This scanner is scoped
 * to SMS-touching classes and separates the read (intercept / inbox), the send, the suppression,
 * and explicit OTP targeting.
 * <ul>
 *   <li><b>sms_intercept</b> (high) — reads an incoming SMS body
 *       ({@code SmsMessage.createFromPdu} / {@code getMessageBody} / {@code getDisplayMessageBody}
 *       in an {@code SMS_RECEIVED} flow) — OTP/2FA capture.</li>
 *   <li><b>sms_send</b> (high) — {@code SmsManager.sendTextMessage} /
 *       {@code sendMultipartTextMessage} — silent SMS send (premium fraud / propagation).</li>
 *   <li><b>sms_abort_broadcast</b> (high) — {@code abortBroadcast()} in an SMS receiver — hides the
 *       message from the user / other apps.</li>
 *   <li><b>sms_read_inbox</b> (medium) — queries {@code content://sms} — reads stored messages.</li>
 *   <li><b>sms_otp_targeting</b> (high) — OTP / one-time-code / 2FA keyword in an SMS class.</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * interceptsSms, sendsSms, truncated}}.
 */
@Command(name = "sms-scan",
		description = "Scan for SMS interception / abuse (MASVS MSTG-PLATFORM): SMS_RECEIVED interception of OTP bodies, silent SmsManager.sendTextMessage (premium fraud), abortBroadcast suppression, content://sms inbox reads. Companion to notification-listener-scan")
public class SmsScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Class-level gate: only classes that touch SMS. */
	private static final Pattern SMS_MARKER = Pattern.compile(
			"SmsManager|SMS_RECEIVED|android\\.provider\\.Telephony|SmsMessage|getMessageBody|"
					+ "sendTextMessage|sendMultipartTextMessage|content://sms|Telephony\\.Sms");

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
			new Rule("SmsMessage\\.createFromPdu\\s*\\(|getMessageBody\\s*\\(|getDisplayMessageBody\\s*\\(|getOriginatingAddress\\s*\\(",
					"sms_intercept", "high",
					"Reads an incoming SMS body (createFromPdu / getMessageBody / getDisplayMessageBody) — captures OTP/2FA codes texted by banks; the SMS half of credential theft"),
			new Rule("sendTextMessage\\s*\\(|sendMultipartTextMessage\\s*\\(|sendDataMessage\\s*\\(",
					"sms_send", "high",
					"Sends SMS programmatically (SmsManager.sendTextMessage / sendMultipartTextMessage) — silent premium-SMS fraud or worm-style self-propagation; verify recipient and user consent"),
			new Rule("abortBroadcast\\s*\\(",
					"sms_abort_broadcast", "high",
					"abortBroadcast() in an SMS receiver — suppresses the incoming message so the user / other apps never see it (OTP hidden after theft)"),
			new Rule("(?i)\\b(otp|one[-_ ]?time[-_ ]?(code|password)|verification[-_ ]?code|2fa|two[-_ ]?factor|auth[-_ ]?code|passcode)\\b",
					"sms_otp_targeting", "high",
					"OTP / one-time-code / 2FA keyword in an SMS class — evidence the SMS handling targets second factors"),
			new Rule("content://sms|Telephony\\.Sms\\.(CONTENT_URI|Inbox)",
					"sms_read_inbox", "medium",
					"Queries the SMS inbox (content://sms) — reads stored messages including historical OTPs; requires READ_SMS"));

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
		boolean interceptsSms = false;
		boolean sendsSms = false;

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
			if (code == null || code.isEmpty() || !SMS_MARKER.matcher(code).find()) {
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
					if ("sms_otp_targeting".equals(r.kind)) {
						if (reportedOtp) {
							break; // one OTP-keyword finding per class to avoid noise
						}
						reportedOtp = true;
					}
					findings.add(finding(fullName, i + 1, r.kind, r.severity, r.detail));
					if ("high".equals(r.severity)) {
						highSeverityCount++;
					}
					if ("sms_intercept".equals(r.kind)) {
						interceptsSms = true;
					} else if ("sms_send".equals(r.kind)) {
						sendsSms = true;
					}
					break; // one finding per line — first (highest-severity) rule wins
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("interceptsSms", interceptsSms);
		data.put("sendsSms", sendsSms);
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
		return "sms-scan";
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
