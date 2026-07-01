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
import jadx.api.ResourceFile;

/**
 * Scans for VPN-based full traffic interception. A {@link android.net.VpnService} subclass
 * whose {@code Builder} calls {@code establish()} (after {@code addRoute / addAddress}) gives
 * the app a raw network TUN — every packet in and out of the device can be captured,
 * modified, or redirected, even over TLS if the app also installs a local proxy / CA. This is
 * the "man-in-the-middle on your own phone" capability, dual-use (enterprise VPN vs. spyware).
 * Reports the VpnService subclass, the prepare/establish flow, and the route interception.
 * MASVS MSTG-NETWORK / MSTG-PLATFORM. Distinct from {@code ssl-scan} (TLS trust) and
 * {@code network-traffic-scan} (cleartext) — this is the tunnel primitive itself.
 *
 * <p>Returns {@code {findings, count, highSeverityCount, hasVpnService, canInterceptTraffic,
 * vpnClasses, hasManifestVpnBinding}}.
 */
@Command(name = "vpn-service-scan",
		description = "Scan for VpnService subclasses + Builder.establish/addRoute (full traffic interception capability)")
public class VpnServiceScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern VPN_MARKER = Pattern.compile(
			"VpnService|VpnService\\.Builder|BIND_VPN_SERVICE|android\\.net\\.VpnService");

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
			new Rule("extends\\s+VpnService",
					"vpn_service_subclass", "medium",
					"Subclass of VpnService — declares a VPN; once granted via prepare() + user consent, runs a local TUN that can carry all device traffic"),
			new Rule("\\.establish\\s*\\(",
					"vpn_establish", "high",
					"VpnService.Builder.establish() — opens the TUN file descriptor; from here the app reads/writes raw IP packets of every app on the device"),
			new Rule("\\.addRoute\\s*\\(|\\.addAddress\\s*\\(|\\.addDnsServer\\s*\\(|\\.addSearchDomain\\s*\\(",
					"vpn_route_intercept", "high",
					"VpnService.Builder.addRoute/addAddress/addDnsServer — redirects traffic (often 0.0.0.0/0 = everything) into the app's tunnel; combined with establish() this is full traffic capture"),
			new Rule("VpnService\\.prepare\\s*\\(",
					"vpn_prepare", "low",
					"VpnService.prepare() — the consent gate before establish(); its presence confirms a real (not stub) VPN flow"),
			new Rule("\\.setMtu\\s*\\(|\\.setSession\\s*\\(|\\.setConfigureIntent\\s*\\(",
					"vpn_builder_config", "low",
					"VpnService.Builder session/MTU/intent configuration — corroborates an active tunnel setup"));

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
		boolean hasVpnService = false;
		boolean canInterceptTraffic = false;
		List<String> vpnClasses = new ArrayList<>();
		boolean hasEstablish = false;
		boolean hasRoute = false;

		boolean hasManifestVpnBinding = false;
		String manifest = loadManifest(decompiler);
		if (manifest != null && manifest.contains("BIND_VPN_SERVICE")) {
			hasManifestVpnBinding = true;
		}

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
			if (code == null || code.isEmpty() || !VPN_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			boolean reportedSubclass = false;
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
					if ("vpn_service_subclass".equals(r.kind) && !reportedSubclass) {
						reportedSubclass = true;
						vpnClasses.add(fullName);
						hasVpnService = true;
					}
					if ("vpn_establish".equals(r.kind)) {
						hasEstablish = true;
					}
					if ("vpn_route_intercept".equals(r.kind)) {
						hasRoute = true;
					}
					break;
				}
			}
		}
		canInterceptTraffic = hasEstablish && hasRoute;

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("hasVpnService", hasVpnService);
		data.put("canInterceptTraffic", canInterceptTraffic);
		data.put("vpnClasses", vpnClasses);
		data.put("hasManifestVpnBinding", hasManifestVpnBinding);
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

	private static String loadManifest(JadxDecompiler decompiler) {
		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name != null && name.replace('\\', '/').endsWith("AndroidManifest.xml")) {
				try {
					return res.loadContent().getText().toString();
				} catch (Exception e) {
					return null;
				}
			}
		}
		return null;
	}

	@Override
	protected String getDaemonCommandName() {
		return "vpn-service-scan";
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
