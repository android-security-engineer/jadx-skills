package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.ManifestUtil;
import jadx.api.JadxDecompiler;

/**
 * Audits the app's Network Security Config (NSC) — the {@code res/xml} policy referenced by
 * {@code android:networkSecurityConfig} that governs TLS trust and cleartext on Android 7+. Native
 * capability: reads the manifest + the referenced XML resource from jadx, no external tool. It
 * resolves the NSC resource, then evaluates each {@code base-config}/{@code domain-config} for:
 * <ul>
 *   <li>{@code cleartextTrafficPermitted="true"} — plaintext HTTP allowed</li>
 *   <li>{@code <trust-anchors><certificates src="user"/>} — trusts user-installed CAs, which makes
 *       interception (and thus MITM during analysis) trivial</li>
 *   <li>presence/absence of {@code <pin-set>} certificate pinning, plus its {@code expiration} —
 *       an expired pin-set silently stops being enforced (Android falls back to system trust),
 *       and a single pin with no backup risks lockout on key rotation</li>
 * </ul>
 * When no NSC is referenced it reports the platform default (cleartext blocked by default on
 * targetSdk ≥ 28, permitted below), so the absence itself is actionable.
 */
@Command(name = "network-security-config", description = "Audit the Network Security Config (cleartext, user-CA trust, certificate pinning)")
public class NetworkSecurityConfigCommand extends AbstractCommand {

	private static final Pattern BASE_CONFIG = Pattern.compile("<base-config\\b([^>]*)>(.*?)</base-config>", Pattern.DOTALL);
	private static final Pattern DOMAIN_CONFIG = Pattern.compile("<domain-config\\b([^>]*)>(.*?)</domain-config>", Pattern.DOTALL);
	private static final Pattern DOMAIN = Pattern.compile("<domain\\b[^>]*>([^<]+)</domain>", Pattern.DOTALL);

	@Override
	protected void applyArgs(Map<String, Object> args) {
		// no options
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		String manifest = ManifestUtil.loadManifestText(decompiler);
		if (manifest == null) {
			return JsonOutput.error("ManifestNotFound", "AndroidManifest.xml not found in resources");
		}

		String appTag = ManifestUtil.extractFirst(manifest, "(<application\\b[^>]*>)");
		String nscRef = appTag == null ? null : attr(appTag, "android:networkSecurityConfig");

		Map<String, Object> data = new LinkedHashMap<>();
		List<Map<String, Object>> findings = new ArrayList<>();

		if (nscRef == null) {
			data.put("referenced", false);
			data.put("note", "No android:networkSecurityConfig declared. Default trust applies; "
					+ "cleartext is blocked by default only when targetSdkVersion >= 28.");
			findings.add(finding("no_nsc", "info", null,
					"App ships no Network Security Config — relies on platform defaults"));
			data.put("findings", findings);
			data.put("findingCount", findings.size());
			return JsonOutput.ok(data);
		}

		data.put("referenced", true);
		data.put("configRef", nscRef);

		// nscRef is like "@xml/network_security_config" or a resource id; load by the bare name.
		String resName = nscRef.contains("/") ? nscRef.substring(nscRef.lastIndexOf('/') + 1) : nscRef;
		String nsc = ManifestUtil.loadResourceText(decompiler, resName);
		if (nsc == null) {
			nsc = ManifestUtil.loadResourceText(decompiler, "network_security_config");
		}
		if (nsc == null) {
			data.put("note", "NSC is referenced (" + nscRef + ") but the XML resource could not be loaded "
					+ "(it may be a binary/arsc-encoded resource).");
			data.put("findings", findings);
			data.put("findingCount", findings.size());
			return JsonOutput.ok(data);
		}

		List<Map<String, Object>> configs = new ArrayList<>();
		// base-config applies to all domains not covered by a domain-config.
		Matcher bm = BASE_CONFIG.matcher(nsc);
		while (bm.find()) {
			configs.add(evalConfig("base-config", null, bm.group(1), bm.group(2), findings));
		}
		Matcher dm = DOMAIN_CONFIG.matcher(nsc);
		while (dm.find()) {
			List<String> domains = new ArrayList<>();
			Matcher dom = DOMAIN.matcher(dm.group(2));
			while (dom.find()) {
				domains.add(dom.group(1).trim());
			}
			configs.add(evalConfig("domain-config", domains, dm.group(1), dm.group(2), findings));
		}

		data.put("configs", configs);
		data.put("findings", findings);
		data.put("findingCount", findings.size());
		return JsonOutput.ok(data);
	}

	private Map<String, Object> evalConfig(String type, List<String> domains, String attrs, String body,
			List<Map<String, Object>> findings) {
		// cleartextTrafficPermitted may sit on the element or be inherited; read what's present.
		String cleartextAttr = attr(attrs, "cleartextTrafficPermitted");
		boolean cleartext = "true".equalsIgnoreCase(cleartextAttr);
		boolean trustsUserCa = body.matches("(?s).*<certificates\\b[^>]*src\\s*=\\s*\"user\".*");
		boolean hasPinning = body.contains("<pin-set");
		String scope = domains == null ? "all (base-config)" : String.join(", ", domains);

		Map<String, Object> cfg = new LinkedHashMap<>();
		cfg.put("type", type);
		if (domains != null) {
			cfg.put("domains", domains);
		}
		cfg.put("cleartextTrafficPermitted", cleartext);
		cfg.put("trustsUserCa", trustsUserCa);
		cfg.put("certificatePinning", hasPinning);

		// Pin-set expiration: once the expiration date passes, Android STOPS enforcing the pins and
		// silently falls back to system trust — a pinning bypass that looks configured but isn't.
		if (hasPinning) {
			Matcher pm = Pattern.compile("<pin-set\\b([^>]*)>", Pattern.DOTALL).matcher(body);
			if (pm.find()) {
				String expiration = attr(pm.group(1), "expiration");
				int pinCount = countMatches(body, "<pin\\b");
				cfg.put("pinCount", pinCount);
				if (expiration != null && !expiration.isEmpty()) {
					cfg.put("pinExpiration", expiration);
					Boolean expired = isPastDate(expiration);
					if (Boolean.TRUE.equals(expired)) {
						cfg.put("pinExpired", true);
						findings.add(finding("pin_set_expired", "high", scope,
								"Certificate pinning expired on " + expiration + " for " + scope
										+ " — Android silently falls back to system trust; pins no longer enforced"));
					} else if (expired != null) {
						cfg.put("pinExpired", false);
					}
				}
				// A single pin with no backup risks permanent lockout on key rotation (Google recommends
				// at least one backup pin); reported as low so operators can weigh availability vs. rigor.
				if (pinCount == 1) {
					findings.add(finding("pin_set_no_backup", "low", scope,
							"pin-set for " + scope + " has a single pin and no backup — key rotation "
									+ "would brick TLS; include a backup pin"));
				}
			}
		}

		if (cleartext) {
			findings.add(finding("cleartext_permitted", "medium", scope,
					"cleartextTrafficPermitted=\"true\" allows plaintext HTTP for " + scope));
		}
		if (trustsUserCa) {
			findings.add(finding("trusts_user_ca", "medium", scope,
					"Trusts user-installed CAs (src=\"user\") for " + scope + " — eases interception/MITM"));
		}
		return cfg;
	}

	private static Map<String, Object> finding(String kind, String severity, String scope, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		if (scope != null) {
			f.put("scope", scope);
		}
		f.put("detail", detail);
		return f;
	}

	private static String attr(String attrs, String name) {
		Matcher m = Pattern.compile(Pattern.quote(name) + "\\s*=\\s*\"([^\"]*)\"").matcher(attrs);
		return m.find() ? m.group(1) : null;
	}

	private static int countMatches(String text, String regex) {
		Matcher m = Pattern.compile(regex).matcher(text);
		int n = 0;
		while (m.find()) {
			n++;
		}
		return n;
	}

	/**
	 * True if {@code yyyy-MM-dd} (the NSC pin-set expiration format) is strictly before today; false
	 * if today or later; null if it can't be parsed (so callers don't flag a malformed date as expired).
	 */
	static Boolean isPastDate(String yyyyMmDd) {
		try {
			java.text.SimpleDateFormat fmt = new java.text.SimpleDateFormat("yyyy-MM-dd");
			fmt.setLenient(false);
			java.util.Date exp = fmt.parse(yyyyMmDd.trim());
			return exp.before(new java.util.Date());
		} catch (Exception e) {
			return null;
		}
	}

	@Override
	protected String getDaemonCommandName() {
		return "network-security-config";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		return new java.util.HashMap<>();
	}
}
