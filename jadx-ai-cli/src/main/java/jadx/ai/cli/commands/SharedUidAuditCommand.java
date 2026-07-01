package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;

/**
 * Detects {@code android:sharedUserId} in the manifest. Two apps sharing a UID run in the
 * same process and can freely read each other's data — historically a data-sharing /
 * privilege-escalation vector, and since Android 10 the attribute is deprecated (ignored for
 * non-system apps). Reports the declared UID and the residual risk. Absorbs the sharedUserId
 * check from MobSF-style scanners in {@code reference/} (mcp-pentest-android); native over the
 * manifest. A small, focused complement to the manifest family of audits.
 */
@Command(name = "shared-uid-audit",
		description = "Detect android:sharedUserId in the manifest and assess shared-UID data/privilege risk")
public class SharedUidAuditCommand extends AbstractCommand {

	private static final Pattern MANIFEST_TAG = Pattern.compile("<manifest\\b[^>]*>", Pattern.CASE_INSENSITIVE);
	private static final Pattern SHARED_UID = Pattern.compile(
			"android:sharedUserId\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern SHARED_USER_LABEL = Pattern.compile(
			"android:sharedUserLabel\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern PACKAGE = Pattern.compile(
			"\\bpackage\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern UID_STYLE = Pattern.compile("android:sharedUserId\\s*=\\s*\"(android\\.uid\\.[^\"]+)\"");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		// No options.
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		String manifest = CustomPermissionAuditCommand.loadManifest(decompiler);

		Map<String, Object> data = new LinkedHashMap<>();
		if (manifest == null) {
			data.put("hasSharedUserId", false);
			data.put("sharedUserId", null);
			data.put("hasManifest", false);
			return JsonOutput.ok(data);
		}

		// Find the <manifest ...> opening tag (sharedUserId lives there).
		String manifestTag = "";
		Matcher tm = MANIFEST_TAG.matcher(manifest);
		if (tm.find()) {
			manifestTag = tm.group();
		}

		Matcher uidM = SHARED_UID.matcher(manifestTag);
		String sharedUid = uidM.find() ? uidM.group(1) : null;
		String label = firstGroup(SHARED_USER_LABEL, manifestTag);
		String pkg = firstGroup(PACKAGE, manifestTag);

		List<String> issues = new ArrayList<>();
		boolean usesSystemUid = false;
		if (sharedUid != null) {
			issues.add("declares android:sharedUserId — apps sharing this UID run in one process "
					+ "and can read each other's data/files/preferences");
			issues.add("android:sharedUserId is deprecated since Android 10 (ignored for non-system apps)");
			if (UID_STYLE.matcher(manifestTag).find()) {
				usesSystemUid = true;
				issues.add("shares a system UID (android.uid.*) — reserved for platform apps, "
						+ "only installable with platform signature");
			}
		}

		data.put("hasSharedUserId", sharedUid != null);
		data.put("sharedUserId", sharedUid);
		if (label != null) {
			data.put("sharedUserLabel", label);
		}
		data.put("package", pkg);
		data.put("usesSystemUid", usesSystemUid);
		data.put("issues", issues);
		data.put("hasManifest", true);
		return JsonOutput.ok(data);
	}

	private static String firstGroup(Pattern p, String input) {
		Matcher m = p.matcher(input);
		return m.find() ? m.group(1) : null;
	}

	@Override
	protected String getDaemonCommandName() {
		return "shared-uid-audit";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		return new LinkedHashMap<>();
	}
}
