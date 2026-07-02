package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.core.dex.info.AccessInfo;

/**
 * Triage report for the deobfuscation workflow: measures how obfuscated an APK is and points at the
 * machinery to unwind. Native capability: reads jadx's parsed model + decompiled code, no external
 * tool. Produces:
 * <ul>
 *   <li><b>name obfuscation</b> — fraction of classes whose short name looks machine-generated
 *       (single/double letter, {@code a1b2} gibberish), the classic ProGuard/R8/DexGuard signature</li>
 *   <li><b>reflection density</b> — {@code Class.forName}/{@code getMethod}/{@code invoke} call
 *       counts (reflection is how obfuscators hide real call targets)</li>
 *   <li><b>string-decrypt candidates</b> — static {@code String f(String|byte[]|int)} methods, the
 *       shape of a string-decryption routine the obfuscator inserts</li>
 *   <li><b>packer/obfuscator signatures</b> — known markers (DexGuard, Allatori, etc.)</li>
 * </ul>
 */
@Command(name = "obfuscation-report", description = "Measure obfuscation (name mangling, reflection, string decryption, packer signatures) for deobfuscation triage")
public class ObfuscationReportCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only analyse classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Max samples/candidates per category", defaultValue = "50")
	protected int limit = 50;

	// Short, machine-generated short names: 1-2 chars, or letter+digits like "a1", "b2c".
	private static final Pattern OBFUSCATED_NAME = Pattern.compile("^[a-zA-Z]{1,2}$|^[a-z][0-9a-z]{0,2}$|^[A-Z]{1,2}[0-9]+$");
	private static final Pattern REFLECTION = Pattern.compile(
			"Class\\.forName\\(|\\.getDeclaredMethod\\(|\\.getMethod\\(|\\.getDeclaredField\\(|\\.getField\\(|"
					+ "Method\\.invoke\\(|\\.invoke\\(|\\.newInstance\\(");
	// Markers left by common commercial obfuscators/packers.
	private static final String[] PACKER_MARKERS = {
			"com.secneo", "com.qihoo", "com.stub.StubApp", "bangcle", "com.tencent.StubShell",
			"DexGuard", "allatori", "com.dexprotector", "com.ijiami", "secshell", "libjiagu",
	};

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		int totalClasses = 0;
		int obfuscatedClasses = 0;
		int totalMethods = 0;
		int obfuscatedMethods = 0;
		int reflectionCalls = 0;
		List<String> sampleObfuscated = new ArrayList<>();
		List<Map<String, Object>> decryptCandidates = new ArrayList<>();
		List<String> reflectionClasses = new ArrayList<>();
		List<String> packerHits = new ArrayList<>();

		for (JavaClass cls : decompiler.getClasses()) {
			String fullName = cls.getFullName();
			if (packageFilter != null && !fullName.startsWith(packageFilter)) {
				continue;
			}
			totalClasses++;
			if (OBFUSCATED_NAME.matcher(cls.getName()).matches()) {
				obfuscatedClasses++;
				if (sampleObfuscated.size() < limit) {
					sampleObfuscated.add(fullName);
				}
			}
			for (String marker : PACKER_MARKERS) {
				if (fullName.contains(marker) && !packerHits.contains(marker)) {
					packerHits.add(marker);
				}
			}

			for (JavaMethod m : cls.getMethods()) {
				totalMethods++;
				if (OBFUSCATED_NAME.matcher(m.getName()).matches() && !m.isConstructor() && !m.isClassInit()) {
					obfuscatedMethods++;
				}
				if (isDecryptShape(m) && decryptCandidates.size() < limit) {
					Map<String, Object> cand = new LinkedHashMap<>();
					cand.put("className", fullName);
					cand.put("methodName", m.getName());
					cand.put("signature", signature(m));
					decryptCandidates.add(cand);
				}
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
			int refs = countMatches(REFLECTION, code);
			if (refs > 0) {
				reflectionCalls += refs;
				if (reflectionClasses.size() < limit) {
					reflectionClasses.add(fullName + " (" + refs + ")");
				}
			}
		}

		double nameRatio = totalClasses == 0 ? 0.0 : (double) obfuscatedClasses / totalClasses;
		List<Map<String, Object>> findings = new ArrayList<>();
		if (nameRatio >= 0.4) {
			findings.add(finding("heavy_name_obfuscation", "info",
					String.format("%.0f%% of classes have machine-generated names — identifier obfuscation in use",
							nameRatio * 100)));
		}
		if (!packerHits.isEmpty()) {
			findings.add(finding("packer_signature", "high",
					"Known packer/obfuscator markers present: " + String.join(", ", packerHits)));
		}
		if (!decryptCandidates.isEmpty()) {
			findings.add(finding("string_decryption", "medium",
					decryptCandidates.size() + "+ static String(...) methods look like string-decryption routines"));
		}
		if (reflectionCalls >= 20) {
			findings.add(finding("high_reflection", "info",
					reflectionCalls + " reflection call sites — real call targets are likely hidden behind reflection"));
		}

		Map<String, Object> nameObf = new LinkedHashMap<>();
		nameObf.put("totalClasses", totalClasses);
		nameObf.put("obfuscatedClasses", obfuscatedClasses);
		nameObf.put("ratio", round(nameRatio));
		nameObf.put("totalMethods", totalMethods);
		nameObf.put("obfuscatedMethods", obfuscatedMethods);
		nameObf.put("samples", sampleObfuscated);

		Map<String, Object> reflection = new LinkedHashMap<>();
		reflection.put("callCount", reflectionCalls);
		reflection.put("classes", reflectionClasses);

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("nameObfuscation", nameObf);
		data.put("reflection", reflection);
		data.put("stringDecryptCandidates", decryptCandidates);
		data.put("packerSignatures", packerHits);
		data.put("findings", findings);
		data.put("findingCount", findings.size());
		return JsonOutput.ok(data);
	}

	/** A string-decryption routine is typically {@code static String f(String|byte[]|int|long)}. */
	private static boolean isDecryptShape(JavaMethod m) {
		AccessInfo acc = m.getAccessFlags();
		if (acc == null || !acc.isStatic()) {
			return false;
		}
		if (m.getReturnType() == null || !"java.lang.String".equals(m.getReturnType().toString())) {
			return false;
		}
		var args = m.getArguments();
		if (args == null || args.size() != 1) {
			return false;
		}
		String a = args.get(0).toString();
		return "java.lang.String".equals(a) || "byte[]".equals(a) || "int".equals(a) || "long".equals(a)
				|| "char[]".equals(a);
	}

	private static String signature(JavaMethod m) {
		StringBuilder sb = new StringBuilder();
		sb.append(m.getReturnType()).append(' ').append(m.getName()).append('(');
		var args = m.getArguments();
		for (int i = 0; i < args.size(); i++) {
			if (i > 0) {
				sb.append(", ");
			}
			sb.append(args.get(i));
		}
		return sb.append(')').toString();
	}

	private static int countMatches(Pattern p, String text) {
		java.util.regex.Matcher m = p.matcher(text);
		int n = 0;
		while (m.find()) {
			n++;
		}
		return n;
	}

	private static Map<String, Object> finding(String kind, String severity, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("detail", detail);
		return f;
	}

	private static double round(double v) {
		return Math.round(v * 1000.0) / 1000.0;
	}

	@Override
	protected String getDaemonCommandName() {
		return "obfuscation-report";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new java.util.HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
