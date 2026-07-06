package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.SecretPatterns;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;

/**
 * Scans decompiled code and text resources for hardcoded secrets (API keys, tokens, private
 * keys, credentials) using a curated pattern set plus a Shannon-entropy filter for generic
 * high-entropy string literals. The pattern library lives in {@link SecretPatterns} — shared
 * with {@code native-libs} so secrets hidden in {@code .so} files are caught by the same rules.
 */
@Command(name = "secrets-scan", description = "Scan code and resources for hardcoded secrets and credentials")
public class SecretsScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--min-entropy" }, description = "Min Shannon entropy for generic secret detection", defaultValue = "3.5")
	protected double minEntropy = 3.5;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("minEntropy")) {
			this.minEntropy = ((Number) args.get("minEntropy")).doubleValue();
		}
		if (args.containsKey("includeResources")) {
			this.includeResources = Boolean.TRUE.equals(args.get("includeResources"));
		}
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();

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
			if (code == null || code.isEmpty()) {
				continue;
			}
			scanText(code, fullName, "code", findings);
		}

		if (includeResources && findings.size() < limit) {
			scanResources(decompiler, findings);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private void scanResources(JadxDecompiler decompiler, List<Map<String, Object>> findings) {
		for (ResourceFile res : decompiler.getResources()) {
			if (findings.size() >= limit) {
				break;
			}
			ResourceType type = res.getType();
			if (type != ResourceType.XML && type != ResourceType.ARSC && type != ResourceType.MANIFEST) {
				continue;
			}
			try {
				var container = res.loadContent();
				if (container == null) {
					continue;
				}
				var codeInfo = container.getText();
				if (codeInfo != null) {
					scanText(codeInfo.toString(), res.getOriginalName(), "resource", findings);
				}
			} catch (Exception ignored) {
				// skip unreadable resources
			}
		}
	}

	private void scanText(String text, String source, String origin, List<Map<String, Object>> findings) {
		// Delegates to the shared pattern library so secrets-scan and native-libs stay in lock-step.
		SecretPatterns.scanText(text, source, origin, minEntropy, limit, findings);
	}

	@Override
	protected String getDaemonCommandName() {
		return "secrets-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new java.util.HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("minEntropy", minEntropy);
		args.put("includeResources", includeResources);
		args.put("limit", limit);
		return args;
	}
}
