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
 * Scans for location acquisition and the anti-spoofing mock-location check. Covers the classic
 * {@link android.location.LocationManager} ({@code requestLocationUpdates} on
 * {@code GPS_PROVIDER / NETWORK_PROVIDER / PASSIVE_PROVIDER}), the modern
 * {@code FusedLocationProviderClient} (Google Play services), and the geocoding/reverse-geocode
 * path ({@code Geocoder}). The flip side is the anti-cheat / anti-spoof check
 * {@code isFromMockProvider} / {@code isMock} — apps that test it are resisting GPS spoofing
 * (dual-use: defensive anti-fraud vs. an analyst's bypass-target). Reports the providers used,
 * whether background/foreground location is declared, and the mock-detection posture. MASVS
 * MSTG-PRIVACY / MSTG-RESILIENCE. Distinct from {@code privacy-scan} (one PII category among
 * many) — this is the location-flavoured deep dive with provider + mock detail.
 *
 * <p>Returns {@code {findings, count, highSeverityCount, tracksLocation, providers,
 * checksMockLocation, usesFusedLocation}}.
 */
@Command(name = "location-scan",
		description = "Scan for location acquisition (LocationManager/FusedLocation/Geocoder) and mock-location anti-spoof checks")
public class LocationScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern LOC_MARKER = Pattern.compile(
			"LocationManager|LocationProvider|FusedLocationProviderClient|FusedLocation|"
					+ "requestLocationUpdates|getLastKnownLocation|Geocoder|android\\.location|"
					+ "isFromMockProvider|isMock\\b|ACCESS_FINE_LOCATION|GPS_PROVIDER");

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
			new Rule("requestLocationUpdates\\s*\\(",
					"loc_request_updates", "high",
					"LocationManager.requestLocationUpdates — subscribes to ongoing location updates; the live-tracking primitive (background location = continuous surveillance)"),
			new Rule("getLastKnownLocation\\s*\\(|getLastLocation\\s*\\(",
					"loc_last_known", "medium",
					"getLastKnownLocation / getLastLocation — reads the most recent cached fix; cheaper but still a one-shot location read"),
			new Rule("GPS_PROVIDER",
					"loc_gps", "high",
					"Uses GPS_PROVIDER — precise (within metres) satellite location; the high-precision tracking source"),
			new Rule("NETWORK_PROVIDER|PASSIVE_PROVIDER",
					"loc_network", "medium",
					"Uses NETWORK_PROVIDER / PASSIVE_PROVIDER — coarse (cell/wifi) or opportunistic location; less precise but available in background"),
			new Rule("FusedLocationProviderClient|FusedLocation",
					"loc_fused", "medium",
					"Google Play services FusedLocationProviderClient — the modern location API; combines GPS/network adaptively, often the actual source in shipping apps"),
			new Rule("Geocoder\\b|getFromLocation\\s*\\(|getFromLocationName\\s*\\(",
					"loc_geocode", "low",
					"Geocoder getFromLocation / getFromLocationName — converts between coordinates and addresses (reverse geocoding); enriches raw fixes with place names"),
			new Rule("isFromMockProvider\\s*\\(|\\.isMock\\s*\\(",
					"loc_mock_check", "medium",
					"isFromMockProvider / isMock — checks whether the fix came from a mock-location app; a defensive anti-spoof / anti-fraud check (and an analyst's bypass target)"),
			new Rule("removeUpdates\\s*\\(",
					"loc_remove_updates", "low",
					"LocationManager.removeUpdates — stops location updates; its presence (vs. request without remove) indicates a bounded, well-behaved subscription"));

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
		boolean tracksLocation = false;
		List<String> providers = new ArrayList<>();
		boolean checksMockLocation = false;
		boolean usesFusedLocation = false;

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
			if (code == null || code.isEmpty() || !LOC_MARKER.matcher(code).find()) {
				continue;
			}
			tracksLocation = true;

			if (code.contains("GPS_PROVIDER") && !providers.contains("GPS")) {
				providers.add("GPS");
			}
			if ((code.contains("NETWORK_PROVIDER") || code.contains("PASSIVE_PROVIDER"))
					&& !providers.contains("NETWORK/PASSIVE")) {
				providers.add("NETWORK/PASSIVE");
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
					if ("loc_fused".equals(r.kind)) {
						usesFusedLocation = true;
					}
					if ("loc_mock_check".equals(r.kind)) {
						checksMockLocation = true;
					}
					break;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("tracksLocation", tracksLocation);
		data.put("providers", providers);
		data.put("usesFusedLocation", usesFusedLocation);
		data.put("checksMockLocation", checksMockLocation);
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
		return "location-scan";
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
