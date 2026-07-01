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
 * Scans for dynamic code loading — MASVS MSTG-CODE-9 / MSTG-RESILIENCE. Native: reads jadx's parsed
 * model, no external tool.
 *
 * <p>Loading executable code at runtime ({@code DexClassLoader}, {@code InMemoryDexClassLoader},
 * {@code System.load} of a {@code .so} by path, {@code CONTEXT_INCLUDE_CODE}) defeats static review
 * and is the canonical staging mechanism for plugin-style malware and for dropping a second-stage
 * payload. The risk turns critical when the loaded artefact comes from a location an attacker can
 * write — external storage, the network, a downloads folder — because then it is an RCE primitive.
 * Rules:
 * <ul>
 *   <li><b>external_dex_load</b> (high) — a class-loader construction on a line that also references
 *       external/world-writable storage or a URL ({@code getExternalFilesDir}, {@code /sdcard},
 *       {@code http(s)://}, {@code download}).</li>
 *   <li><b>dynamic_dex_load</b> (medium) — any {@code DexClassLoader}/{@code InMemoryDexClassLoader}/
 *       {@code DexFile} use whose source isn't obviously external.</li>
 *   <li><b>native_load_path</b> (medium) — {@code System.load(<path>)} (absolute-path native load,
 *       unlike the normal {@code System.loadLibrary(name)}).</li>
 *   <li><b>include_code_context</b> (medium) — {@code createPackageContext(..., CONTEXT_INCLUDE_CODE)}
 *       executes another package's code.</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * usesDynamicLoading, truncated}}.
 */
@Command(name = "dynamic-loading-scan",
		description = "Scan for dynamic code loading (MASVS MSTG-CODE-9): DexClassLoader/InMemoryDexClassLoader, System.load by path, CONTEXT_INCLUDE_CODE — flagged high when the source is external/world-writable/network")
public class DynamicLoadingScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Class-level gate: only classes that load code at all. */
	private static final Pattern LOADER_MARKER = Pattern.compile(
			"DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|DexFile|System\\.load\\s*\\(|CONTEXT_INCLUDE_CODE|createPackageContext");

	private static final Pattern DEX_LOADER = Pattern.compile(
			"DexClassLoader\\s*\\(|InMemoryDexClassLoader\\s*\\(|BaseDexClassLoader\\s*\\(|DexFile\\.loadDex\\s*\\(|new\\s+DexFile\\s*\\(");

	/** System.load("/abs/path") — but NOT System.loadLibrary("name"), which is the normal case. */
	private static final Pattern NATIVE_LOAD_PATH = Pattern.compile("System\\.load\\s*\\(");

	private static final Pattern INCLUDE_CODE = Pattern.compile("CONTEXT_INCLUDE_CODE");

	/** Markers that the loaded artefact comes from an attacker-influenceable location. */
	private static final Pattern EXTERNAL_SRC = Pattern.compile(
			"getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir|getExternalStoragePublicDirectory|/sdcard|https?://|download|getDownloadCacheDirectory|getContentResolver");

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
		boolean usesDynamicLoading = false;

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
			if (code == null || code.isEmpty() || !LOADER_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;

				if (DEX_LOADER.matcher(line).find()) {
					usesDynamicLoading = true;
					if (EXTERNAL_SRC.matcher(line).find()) {
						findings.add(finding(fullName, ln, "external_dex_load", "high",
								"Class loaded from an external/world-writable/network source — runtime RCE primitive; an attacker who controls that file controls execution"));
						highSeverityCount++;
					} else {
						findings.add(finding(fullName, ln, "dynamic_dex_load", "medium",
								"Dynamic DEX/class loading — defeats static review; verify the loaded artefact is integrity-checked and from app-private storage"));
					}
				} else if (NATIVE_LOAD_PATH.matcher(line).find()) {
					usesDynamicLoading = true;
					boolean ext = EXTERNAL_SRC.matcher(line).find();
					findings.add(finding(fullName, ln, ext ? "external_native_load" : "native_load_path",
							ext ? "high" : "medium",
							ext
									? "Native library loaded by path from an external/network source — attacker-controlled .so is code execution"
									: "System.load(path) loads a .so by absolute path (vs loadLibrary) — verify the path is app-private and the .so integrity-checked"));
					if (ext) {
						highSeverityCount++;
					}
				} else if (INCLUDE_CODE.matcher(line).find()) {
					usesDynamicLoading = true;
					findings.add(finding(fullName, ln, "include_code_context", "medium",
							"createPackageContext(..., CONTEXT_INCLUDE_CODE) executes another package's code — verify the target package is trusted and signature-pinned"));
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("usesDynamicLoading", usesDynamicLoading);
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
		return "dynamic-loading-scan";
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
