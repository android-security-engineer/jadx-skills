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
 * Locates anti-tampering / anti-analysis self-defence in the app — MASVS MSTG-RESILIENCE. Native:
 * reads jadx's parsed model, no external tool.
 *
 * <p>Unlike the other scanners this one is dual-use, and deliberately so. For a <b>defender</b> it
 * answers "does this build actually have resilience controls, and how mature are they?". For the
 * <b>reverse engineer</b> it is a bypass-target inventory: every line below is a check that must be
 * hooked or patched (Frida/Xposed) before dynamic analysis works — it pairs directly with the
 * {@code hook} and {@code frida} commands. Categories:
 * <ul>
 *   <li><b>root</b> — su binary paths, Magisk/SuperSU package names, RootBeer, test-keys.</li>
 *   <li><b>emulator</b> — goldfish/ranchu/qemu, generic Build.FINGERPRINT, Genymotion/VBox markers.</li>
 *   <li><b>debugger</b> — {@code Debug.isDebuggerConnected}, {@code waitingForDebugger}, FLAG_DEBUGGABLE checks.</li>
 *   <li><b>frida_xposed</b> — frida/gum/27042 port, Xposed packages, {@code /proc/self/maps} scans.</li>
 *   <li><b>attestation</b> — SafetyNet / Play Integrity remote attestation.</li>
 * </ul>
 *
 * Returns {@code {findings:[{category,className,lineNumber,detail}], count, categories{...counts...},
 * present{root,emulator,debugger,frida_xposed,attestation}, truncated}}. No severity field — these
 * are <em>defences</em>, not vulnerabilities; their presence is good and their absence is the risk.
 */
@Command(name = "tamper-detection-scan",
		description = "Locate anti-tampering/anti-analysis defences (root/emulator/debugger/Frida-Xposed detection, SafetyNet/Play Integrity) — resilience posture + RE bypass-target inventory")
public class TamperDetectionScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	private static final class Rule {
		final Pattern pattern;
		final String category;
		final String detail;

		Rule(Pattern pattern, String category, String detail) {
			this.pattern = pattern;
			this.category = category;
			this.detail = detail;
		}
	}

	private static final List<Rule> RULES = List.of(
			new Rule(Pattern.compile(
					"/system/(x?bin)/su\\b|\"su\"|test-keys|Superuser\\.apk|com\\.topjohnwu\\.magisk|eu\\.chainfire|com\\.noshufou\\.android\\.su|RootBeer|isDeviceRooted|checkRootMethod|/system/app/Superuser|busybox|magisk"),
					"root",
					"Root-detection marker (su path / Magisk-SuperSU package / RootBeer / test-keys)"),
			new Rule(Pattern.compile(
					"goldfish|ranchu|\\bqemu\\b|generic_x86|sdk_gphone|Genymotion|genymotion|vbox86|\"unknown\"\\s*\\)|Build\\.FINGERPRINT|isEmulator|/dev/socket/qemud|/dev/qemu_pipe"),
					"emulator",
					"Emulator-detection marker (goldfish/ranchu/qemu / generic fingerprint / Genymotion / VBox)"),
			new Rule(Pattern.compile(
					"isDebuggerConnected\\s*\\(|waitingForDebugger\\s*\\(|ApplicationInfo\\.FLAG_DEBUGGABLE|FLAG_DEBUGGABLE|android\\.os\\.Debug|Debug\\.threadCpuTimeNanos"),
					"debugger",
					"Debugger-detection marker (isDebuggerConnected / FLAG_DEBUGGABLE / timing check)"),
			new Rule(Pattern.compile(
					"\\bfrida\\b|gum-js-loop|gmain|re\\.frida|frida-server|\\b27042\\b|/proc/self/maps|/proc/self/status|de\\.robv\\.android\\.xposed|XposedBridge|xposed|libsubstrate|Substrate|EdXposed|LSPosed"),
					"frida_xposed",
					"Instrumentation-detection marker (Frida server/port-27042 / maps scan / Xposed-Substrate)"),
			new Rule(Pattern.compile(
					"SafetyNet|attest\\s*\\(|PlayIntegrity|IntegrityManager|IntegrityTokenRequest|com\\.google\\.android\\.gms\\.safetynet|nonce"),
					"attestation",
					"Remote attestation marker (SafetyNet / Play Integrity)"));

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
		Map<String, Integer> categories = new LinkedHashMap<>();
		for (Rule r : RULES) {
			categories.putIfAbsent(r.category, 0);
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
			if (code == null || code.isEmpty()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;
				for (Rule r : RULES) {
					if (r.pattern.matcher(line).find()) {
						findings.add(finding(fullName, ln, r.category, r.detail));
						categories.merge(r.category, 1, Integer::sum);
						break; // one category per line
					}
				}
			}
		}

		Map<String, Object> present = new LinkedHashMap<>();
		for (Map.Entry<String, Integer> e : categories.entrySet()) {
			present.put(e.getKey(), e.getValue() > 0);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("categories", categories);
		data.put("present", present);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String cls, int line, String category, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("category", category);
		f.put("className", cls);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "tamper-detection-scan";
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
