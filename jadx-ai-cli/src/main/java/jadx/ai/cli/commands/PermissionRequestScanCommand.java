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
 * Permission-request scanner — MASVS MSTG-PLATFORM-1.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects runtime permission request patterns: requestPermissions calls,
 * permission check patterns, broad permission groups, and missing
 * shouldShowRequestPermissionRationale. Complements
 * {@code permission-risk-map} (manifest-declared permissions → risk API mapping)
 * by focusing on <b>runtime permission request flow and usability</b>.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code request_dangerous_permission} — requestPermissions() call with a
 *       dangerous permission string — app requests runtime permissions</li>
 *   <li>{@code no_rationale} — requestPermissions without corresponding
 *       shouldShowRequestPermissionRationale — poor UX, user gets no explanation
 *       before permission prompt</li>
 *   <li>{@code broad_permission_group} — Requesting broad permission groups
 *       (READ_CONTACTS + WRITE_CONTACTS, READ_EXTERNAL_STORAGE + WRITE_EXTERNAL_STORAGE,
 *       ACCESS_FINE_LOCATION + ACCESS_COARSE_LOCATION) when narrower would suffice</li>
 *   <li>{@code check_permission} — checkSelfPermission / ContextCompat.checkSelfPermission
 *       — app checks before requesting; positive indicator for proper flow</li>
 *   <li>{@code onRequestPermissionsResult} — Override of onRequestPermissionsResult —
 *       app handles permission results; positive indicator</li>
 *   <li>{@code permission_denial_no_graceful} — Permission request without
 *       onRequestPermissionsResult handling or ActivityCompat.shouldShowRequestPermissionRationale
 *       — app may crash or behave unexpectedly on denial</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasPermissionCheck, hasRationale, truncated}}.
 */
@Command(name = "permission-request-scan",
		description = "Audit runtime permission requests (MASVS MSTG-PLATFORM-1): requestPermissions usage, missing rationale, broad permission groups, permission check patterns. Complements permission-risk-map (declared permissions)")
public class PermissionRequestScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with permission markers. */
	private static final Pattern PERM_MARKER = Pattern.compile(
			"requestPermissions|checkSelfPermission|shouldShowRequestPermissionRationale|"
					+ "onRequestPermissionsResult|permission|PERMISSION|"
					+ "ActivityCompat|ContextCompat");

	private static final Pattern REQUEST_PERMS = Pattern.compile(
			"requestPermissions\\s*\\(|ActivityCompat\\.requestPermissions|"
					+ "requestPermissions\\s*\\(\\s*this|"
					+ "requestPermissions\\s*\\(\\s*activity");
	private static final Pattern NO_RATIONALE = Pattern.compile(
			"requestPermissions\\s*\\(");
	private static final Pattern BROAD_GROUP = Pattern.compile(
			"READ_CONTACTS.*WRITE_CONTACTS|WRITE_CONTACTS.*READ_CONTACTS|"
					+ "READ_EXTERNAL_STORAGE.*WRITE_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE.*READ_EXTERNAL_STORAGE|"
					+ "ACCESS_FINE_LOCATION.*ACCESS_COARSE_LOCATION|ACCESS_COARSE_LOCATION.*ACCESS_FINE_LOCATION|"
					+ "READ_PHONE_STATE.*CALL_PHONE|CALL_PHONE.*READ_PHONE_STATE");
	private static final Pattern CHECK_PERM = Pattern.compile(
			"checkSelfPermission\\s*\\(|ContextCompat\\.checkSelfPermission|"
					+ "PERMISSION_GRANTED|PERMISSION_DENIED");
	private static final Pattern ON_RESULT = Pattern.compile(
			"onRequestPermissionsResult\\s*\\(");
	private static final Pattern SHOULD_RATIONALE = Pattern.compile(
			"shouldShowRequestPermissionRationale\\s*\\(|"
					+ "ActivityCompat\\.shouldShowRequestPermissionRationale");

	private static final class Rule {
		final Pattern pattern;
		final String kind;
		final String severity;
		final String detail;
		Rule(Pattern pattern, String kind, String severity, String detail) {
			this.pattern = pattern;
			this.kind = kind;
			this.severity = severity;
			this.detail = detail;
		}
	}

	private static final Rule[] RULES = {
		new Rule(BROAD_GROUP, "broad_permission_group", "medium",
				"Broad permission group — requesting both read+write of the same resource "
						+ "(contacts/storage/location); consider requesting only the minimal "
						+ "permission needed"),
		new Rule(REQUEST_PERMS, "request_dangerous_permission", "info",
				"Runtime permission request — app requests dangerous permissions at runtime; "
						+ "verify each request is necessary and minimal"),
		new Rule(CHECK_PERM, "check_permission", "info",
				"Permission check before request — positive indicator; app follows "
						+ "check-then-request pattern"),
		new Rule(ON_RESULT, "onRequestPermissionsResult", "info",
				"Permission result handler — positive indicator; app handles "
						+ "permission grant/deny results"),
		new Rule(SHOULD_RATIONALE, "permission_rationale", "info",
				"Permission rationale provided — positive indicator; app explains "
						+ "why a permission is needed before requesting it"),
	};

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
		boolean hasPermissionCheck = false;
		boolean hasRationale = false;

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
			if (code == null || code.isEmpty() || !PERM_MARKER.matcher(code).find()) {
				continue;
			}

			// Class-level checks
			boolean classRequestsPerm = NO_RATIONALE.matcher(code).find();
			boolean classHasRationale = SHOULD_RATIONALE.matcher(code).find();
			boolean classHasResult = ON_RESULT.matcher(code).find();
			boolean classHasCheck = CHECK_PERM.matcher(code).find();

			if (classHasCheck) {
				hasPermissionCheck = true;
			}
			if (classHasRationale) {
				hasRationale = true;
			}

			// Request without rationale
			if (classRequestsPerm && !classHasRationale) {
				findings.add(finding("no_rationale", "medium", fullName, 0,
						"requestPermissions without shouldShowRequestPermissionRationale — "
								+ "user gets no explanation before permission prompt; add rationale "
								+ "to explain why the permission is needed"));
			}

			// Request without result handler
			if (classRequestsPerm && !classHasResult) {
				findings.add(finding("permission_denial_no_graceful", "medium", fullName, 0,
						"requestPermissions without onRequestPermissionsResult — app may "
								+ "crash or behave unexpectedly if permission is denied; "
								+ "add a result handler"));
			}

			if (findings.size() >= limit) {
				break;
			}

			// Per-line rule detection (first-match-wins, ONE/class per kind)
			TreeSet<String> reportedKinds = new TreeSet<>();
			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!reportedKinds.contains(r.kind) && r.pattern.matcher(line).find()) {
						findings.add(finding(r.kind, r.severity, fullName, i + 1, r.detail));
						reportedKinds.add(r.kind);
						if ("high".equals(r.severity)) {
							highSeverityCount++;
						}
						break;
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("hasPermissionCheck", hasPermissionCheck);
		data.put("hasRationale", hasRationale);
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
		return "permission-request-scan";
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
