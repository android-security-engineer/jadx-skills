package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;

/**
 * Audits <em>custom</em> permissions declared in {@code AndroidManifest.xml}: their
 * {@code protectionLevel}, whether they guard sensitive exported components, and the
 * classic misconfigurations (a {@code normal}-level permission protecting exported
 * surface; a permission never actually enforced by any {@code android:permission}
 * attribute; the deprecated {@code signatureOrSystem}). Absorbs the manifest-permission
 * analysis from MobSF-style static scanners (the project-family in {@code reference/}),
 * reimplemented natively over jadx's resource model. Complements {@code manifest-audit} /
 * {@code unsafe-export-scan} (which look at exported flags) by focusing on the permission
 * declarations themselves.
 */
@Command(name = "custom-permission-audit",
		description = "Audit custom <permission> declarations: protectionLevel, sensitive-component guards, misconfigurations")
public class CustomPermissionAuditCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum permissions to report", defaultValue = "100")
	protected int limit = 100;

	private static final Pattern PERMISSION_TAG = Pattern.compile(
			"<permission\\b[^>]*>", Pattern.CASE_INSENSITIVE);
	private static final Pattern ATTR_NAME = Pattern.compile(
			"android:name\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern ATTR_PROT = Pattern.compile(
			"android:protectionLevel\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern ATTR_FLAGS = Pattern.compile(
			"android:permissionFlags\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern COMPONENT_WITH_PERM = Pattern.compile(
			"<(activity|service|receiver|provider)\\b[^>]*\\bandroid:permission\\s*=\\s*\"([^\"]+)\"");
	private static final Pattern USES_PERMISSION = Pattern.compile(
			"<uses-permission\\b[^>]*\\bandroid:name\\s*=\\s*\"([^\"]+)\"");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		String manifest = loadManifest(decompiler);
		if (manifest == null) {
			return JsonOutput.ok(new LinkedHashMap<>(Map.of(
					"permissions", List.of(),
					"permissionCount", 0,
					"hasManifest", false)));
		}

		// 1. Parse <permission> declarations
		List<Map<String, Object>> permissions = new ArrayList<>();
		List<String> customNames = new ArrayList<>();
		Matcher tagM = PERMISSION_TAG.matcher(manifest);
		while (tagM.find() && permissions.size() < limit) {
			String tag = tagM.group();
			String name = firstGroup(ATTR_NAME, tag);
			String protLevel = firstGroup(ATTR_PROT, tag);
			String flags = firstGroup(ATTR_FLAGS, tag);
			if (name == null) {
				continue;
			}
			customNames.add(name);

			String baseLevel = parseBaseLevel(protLevel);
			Map<String, Object> p = new LinkedHashMap<>();
			p.put("name", name);
			p.put("protectionLevel", protLevel != null ? protLevel : "(default: normal)");
			p.put("baseLevel", baseLevel);
			if (flags != null) {
				p.put("permissionFlags", flags);
			}

			List<String> issues = new ArrayList<>();
			if ("normal".equals(baseLevel) || baseLevel == null) {
				// normal-level custom permissions are enforceable by any app — flag as review point
				issues.add("normal-level custom permission (enforceable by any app)");
			}
			if (protLevel != null && protLevel.contains("signatureOrSystem")) {
				issues.add("deprecated signatureOrSystem level (use signature|privileged)");
			}
			if (protLevel != null && protLevel.contains("privileged")) {
				// privileged only matters for system apps; note it
				issues.add("privileged level (system-app only)");
			}
			p.put("issues", issues);
			permissions.add(p);
		}

		// 2. Which custom permissions actually guard a component?
		java.util.Map<String, Integer> guardedBy = new java.util.TreeMap<>();
		Matcher compM = COMPONENT_WITH_PERM.matcher(manifest);
		while (compM.find()) {
			guardedBy.merge(compM.group(2), 1, Integer::sum);
		}
		for (Map<String, Object> p : permissions) {
			String name = (String) p.get("name");
			Integer guardCount = guardedBy.get(name);
			p.put("guardsComponents", guardCount != null ? guardCount : 0);
			if (guardCount == null) {
				@SuppressWarnings("unchecked")
				List<String> issues = (List<String>) p.get("issues");
				issues.add("declared but never enforced by any component android:permission");
			}
		}

		// 3. Which custom permissions are requested via <uses-permission>?
		java.util.Set<String> used = new java.util.HashSet<>();
		Matcher usesM = USES_PERMISSION.matcher(manifest);
		while (usesM.find()) {
			used.add(usesM.group(1));
		}
		for (Map<String, Object> p : permissions) {
			p.put("requestedBySelf", used.contains(p.get("name")));
		}

		// Summary flags
		long sensitiveGuards = permissions.stream()
				.filter(p -> ((Number) p.get("guardsComponents")).intValue() > 0)
				.count();
		long normalLevel = permissions.stream()
				.filter(p -> "normal".equals(p.get("baseLevel")))
				.count();
		long unenforced = permissions.stream()
				.filter(p -> ((Number) p.get("guardsComponents")).intValue() == 0)
				.count();

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("permissions", permissions);
		data.put("permissionCount", permissions.size());
		data.put("guardSensitiveComponents", sensitiveGuards);
		data.put("normalLevelCount", normalLevel);
		data.put("unenforcedCount", unenforced);
		data.put("hasManifest", true);
		// Silent-truncation signal: permissions is capped at `limit` via a while-guard, and EVERY
		// downstream computation (guardSensitiveComponents, normalLevelCount, unenforcedCount) operates
		// only on the truncated list — so a manifest with >limit custom <permission> tags silently drops
		// the tail, and the guard cross-ref never sees the dropped permissions. An FN amplifier.
		data.put("truncated", permissions.size() >= limit);
		return JsonOutput.ok(data);
	}

	/** protectionLevel may be a flag union (e.g. "0x11") or a base name (normal/dangerous/signature). */
	private static String parseBaseLevel(String protLevel) {
		if (protLevel == null) {
			return null;
		}
		String low = protLevel.toLowerCase();
		for (String base : new String[] { "dangerous", "signature", "normal", "privileged" }) {
			if (low.contains(base)) {
				return base;
			}
		}
		// Numeric levels: 0=normal,1=dangerous,2=signature,3=signatureOrSystem(0x11),0x40=privileged
		if (low.startsWith("0x")) {
			try {
				int v = Integer.decode(low);
				switch (v) {
					case 0: return "normal";
					case 1: return "dangerous";
					case 2: return "signature";
					case 3: case 0x11: return "signature";
					case 0x40: return "privileged";
					default: return "normal";
				}
			} catch (NumberFormatException e) {
				return null;
			}
		}
		return null;
	}

	private static String firstGroup(Pattern p, String input) {
		Matcher m = p.matcher(input);
		return m.find() ? m.group(1) : null;
	}

	static String loadManifest(JadxDecompiler decompiler) {
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
		return "custom-permission-audit";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("limit", limit);
		return args;
	}
}
