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
 * Scans for SIM / carrier / device-identifier reads — the device-fingerprinting surface that
 * {@code privacy-scan} only touches at a high level. {@link android.telephony.TelephonyManager}
 * exposes stable device identifiers — {@code getSimSerialNumber (ICCID)}, {@code
 * getSubscriberId (IMSI)}, {@code getDeviceId (IMEI on <API 26)}, {@code getLine1Number
 * (phone number)}, {@code getNetworkOperator / getSimOperator} (carrier) — and
 * {@link android.telephony.SubscriptionManager} adds multi-SIM enumeration
 * ({@code getActiveSubscriptionInfoList}). Each is high-value PII and a tracking handle.
 * Reports which identifiers are read, the carrier-info reads, and the subscription-manager
 * surface. MASVS MSTG-PRIVACY / MSTG-STORAGE. Distinct from {@code privacy-scan} (broad PII
 * sweep) — this is the SIM/Telephony deep dive keyed on the specific identifier APIs.
 *
 * <p>Returns {@code {findings, count, highSeverityCount, readsSimIdentifiers,
 * identifiers, readsCarrierInfo, usesSubscriptionManager}}.
 */
@Command(name = "sim-info-scan",
		description = "Scan for SIM/carrier/device-identifier reads (ICCID/IMSI/IMEI/phone number, SubscriptionManager)")
public class SimInfoScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern SIM_MARKER = Pattern.compile(
			"TelephonyManager|SubscriptionManager|getSimSerialNumber|getSubscriberId|getDeviceId|"
					+ "getLine1Number|getSimOperator|getNetworkOperator|android\\.telephony");

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

	private static final List<Rule> RULES = List.of(
			new Rule("getSimSerialNumber\\s*\\(",
					"sim_iccid", "high",
					"TelephonyManager.getSimSerialNumber — the SIM's ICCID, a unique, persistent SIM identifier; high-value device fingerprint / tracking handle"),
			new Rule("getSubscriberId\\s*\\(",
					"sim_imsi", "high",
					"TelephonyManager.getSubscriberId — the IMSI, a unique subscriber identifier tied to the SIM and carrier account; persistent across factory resets of the SIM"),
			new Rule("getDeviceId\\s*\\(",
					"sim_imei", "high",
					"TelephonyManager.getDeviceId — the device IMEI/MEID (deprecated API < 26); the canonical hardware serial, used for tracking and fraud"),
			new Rule("getLine1Number\\s*\\(",
					"sim_phone_number", "high",
					"TelephonyManager.getLine1Number — the SIM's phone number (MSISDN); highly sensitive PII, only readable on some carriers"),
			new Rule("getSimOperator\\s*\\(|getSimOperatorName\\s*\\(|getNetworkOperator\\s*\\(|getNetworkOperatorName\\s*\\(",
					"sim_carrier", "medium",
					"TelephonyManager getSimOperator / getNetworkOperator — the SIM's MCC+MNC carrier code; coarse but persistent carrier identifier"),
			new Rule("getSimCountryIso\\s*\\(|getNetworkCountryIso\\s*\\(",
					"sim_country", "low",
					"TelephonyManager getSimCountryIso / getNetworkCountryIso — the SIM's registered country; a location-adjacent signal"),
			new Rule("SubscriptionManager|getActiveSubscriptionInfoList\\s*\\(|getActiveSubscriptionInfoCount\\s*\\(",
					"sim_subscription_manager", "medium",
					"SubscriptionManager — enumerates active SIM subscriptions (multi-SIM/DSDS devices); richer device fingerprint than single-SIM APIs"),
			new Rule("getSimState\\s*\\(|getSimCount\\s*\\(",
					"sim_state", "low",
					"TelephonyManager.getSimState / getSimCount — SIM presence/state read; corroborates a SIM-aware flow"));

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
		boolean readsSimIdentifiers = false;
		List<String> identifiers = new ArrayList<>();
		boolean readsCarrierInfo = false;
		boolean usesSubscriptionManager = false;

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
			if (code == null || code.isEmpty() || !SIM_MARKER.matcher(code).find()) {
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
						readsSimIdentifiers = true;
					}
					if ("sim_iccid".equals(r.kind) && !identifiers.contains("ICCID")) {
						identifiers.add("ICCID");
					}
					if ("sim_imsi".equals(r.kind) && !identifiers.contains("IMSI")) {
						identifiers.add("IMSI");
					}
					if ("sim_imei".equals(r.kind) && !identifiers.contains("IMEI")) {
						identifiers.add("IMEI");
					}
					if ("sim_phone_number".equals(r.kind) && !identifiers.contains("Phone")) {
						identifiers.add("Phone");
					}
					if ("sim_carrier".equals(r.kind)) {
						readsCarrierInfo = true;
					}
					if ("sim_subscription_manager".equals(r.kind)) {
						usesSubscriptionManager = true;
					}
					break;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("readsSimIdentifiers", readsSimIdentifiers);
		data.put("identifiers", identifiers);
		data.put("readsCarrierInfo", readsCarrierInfo);
		data.put("usesSubscriptionManager", usesSubscriptionManager);
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
		return "sim-info-scan";
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
