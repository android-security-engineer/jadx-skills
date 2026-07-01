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
 * Runtime-integrity scanner — MASVS MSTG-RESILIENCE-2/3.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects runtime integrity self-checks: signature verification at runtime,
 * Dex CRC checks, debuggable-detection, emulator detection, and Frida/Xposed
 * runtime detection. Complements {@code tamper-detection-scan} (static anti-tamper
 * markers) by focusing on <b>runtime verification logic</b> rather than declaration
 * of protection intent.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code runtime_signature_verify} — PackageManager.getSignatures / GET_SIGNATURES
 *       used to verify the app's own signature at runtime — detects repackaging</li>
 *   <li>{@code dex_crc_check} — CRC32 / Adler32 / checksum verification of DEX files
 *       — detects code modification</li>
 *   <li>{@code debugger_detect} — Debug.isDebuggerConnected / android.os.Debug /
 *       ptrace(PTRACE_TRACEME) — runtime debugger detection</li>
 *   <li>{@code emulator_detect} — Emulator fingerprinting (goldfish/ranchu Build,
 *       'generic' model, no battery, baseband version '1.0.0.0', QEMU drivers,
 *       /dev/qemu_pipe, 'nox'/'bluestacks'/'memu') — runtime emulator detection</li>
 *   <li>{@code frida_detect} — Frida runtime detection (frida-server port 27042,
 *       'frida' in /proc/self/maps, D-Bus protocol probe, 'LIBFRIDA',
 *       're.frida.server') — detects Frida instrumentation</li>
 *   <li>{@code xposed_detect} — Xposed runtime detection (de.robv.android.xposed,
 *       XposedBridge, XC_MethodHook, handleHookedMethod,
 *       /proc/self/maps 'xposed') — detects Xposed framework</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasSignatureVerify, hasDexCrc, hasDebuggerDetect,
 * hasEmulatorDetect, hasFridaDetect, hasXposedDetect, truncated}}.
 */
@Command(name = "runtime-integrity-scan",
		description = "Detect runtime integrity self-checks (MASVS MSTG-RESILIENCE-2/3): signature verification, DEX CRC, debugger/emulator/Frida/Xposed detection. Complements tamper-detection-scan (static markers)")
public class RuntimeIntegrityScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with integrity-check markers. */
	private static final Pattern INTEGRITY_MARKER = Pattern.compile(
			"getSignatures|GET_SIGNATURES|PackageInfo|CRC32|Adler32|checksum|"
					+ "isDebuggerConnected|android\\.os\\.Debug|PTRACE_TRACEME|ptrace|"
					+ "goldfish|ranchu|generic|qemu_pipe|LIBFRIDA|frida|"
					+ "XposedBridge|XposedHelpers|de\\.robv\\.android\\.xposed|"
					+ "emulator|isEmulator|detectEmulator|Bluestacks|Nox|MEMU");

	private static final Pattern SIGNATURE_VERIFY = Pattern.compile(
			"getSignatures\\s*\\(|GET_SIGNATURES|packageInfo\\.signatures|"
					+ "PackageManager\\.GET_SIGNING_CERTIFICATES|"
					+ "getPackageInfo.*GET_SIGNATURES|verifySignature|"
					+ "Signature\\s*\\[\\s*\\]|toByteArray\\s*\\(\\)\\s*.*MessageDigest");
	private static final Pattern DEX_CRC = Pattern.compile(
			"CRC32|Adler32|checksum|DexFile.*crc|getCrc|"
					+ "ZipEntry.*getCrc|verifyDexChecksum|checkDexIntegrity");
	private static final Pattern DEBUGGER_DETECT = Pattern.compile(
			"isDebuggerConnected|android\\.os\\.Debug|PTRACE_TRACEME|"
					+ "ptrace\\s*\\(PTRACE_TRACEME|TracerPid|"
					+ "Debug\\.isDebuggerConnected|debuggerAttached|"
					+ "waitForDebugger|android\\.os\\.Debug\\.waitingForDebugger");
	private static final Pattern EMULATOR_DETECT = Pattern.compile(
			"goldfish|ranchu|Build\\.MODEL.*generic|Build\\.HARDWARE.*goldfish|"
					+ "Build\\.PRODUCT.*sdk|Build\\.FINGERPRINT.*generic|"
					+ "qemu_pipe|/dev/qemu|LIBQEMU|qemu_pipe|"
					+ "isEmulator|detectEmulator|checkEmulator|"
					+ "Bluestacks|NOX|MEMU|LDPlayer|"
					+ "baseband.*1\\.0\\.0\\.0|battery.*not_present|"
					+ "hasBattery|isCharging.*always|Genymotion|"
					+ "ueventd\\.rc|init\\.goldfish");
	private static final Pattern FRIDA_DETECT = Pattern.compile(
			"frida|27042|LIBFRIDA|frida-agent|frida-server|"
					+ "re\\.frida\\.server|linjector|"
					+ "/proc/self/maps.*frida|/proc/self/maps.*linjector|"
					+ "D-Bus.*org\\.freedesktop|frida_rpc|"
					+ "listenPort.*27042|frida-gadget");
	private static final Pattern XPOSED_DETECT = Pattern.compile(
			"XposedBridge|XposedHelpers|de\\.robv\\.android\\.xposed|"
					+ "XC_MethodHook|handleHookedMethod|XSharedPreferences|"
					+ "IXposedHookLoadPackage|IXposedHookZygoteInit|"
					+ "/proc/self/maps.*xposed|xposed_init|"
					+ "XposedInit|sedation_loader|"
					+ "LSPosed|EdXposed|TaiChi");

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
		new Rule(SIGNATURE_VERIFY, "runtime_signature_verify", "info",
				"Runtime signature verification — app verifies its own signing certificate "
						+ "at runtime to detect repackaging; a positive defence indicator"),
		new Rule(DEX_CRC, "dex_crc_check", "info",
				"DEX CRC/checksum verification — app checks DEX file integrity at runtime "
						+ "to detect code modification; a positive defence indicator"),
		new Rule(DEBUGGER_DETECT, "debugger_detect", "info",
				"Runtime debugger detection — app checks for attached debuggers; "
						+ "a positive defence indicator"),
		new Rule(FRIDA_DETECT, "frida_detect", "info",
				"Runtime Frida detection — app checks for Frida instrumentation framework; "
						+ "a positive defence indicator for anti-RE"),
		new Rule(XPOSED_DETECT, "xposed_detect", "info",
				"Runtime Xposed detection — app checks for Xposed framework; "
						+ "a positive defence indicator for anti-RE"),
		new Rule(EMULATOR_DETECT, "emulator_detect", "info",
				"Runtime emulator detection — app fingerprint the runtime environment "
						+ "to detect emulators; a positive defence indicator"),
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
		boolean hasSignatureVerify = false;
		boolean hasDexCrc = false;
		boolean hasDebuggerDetect = false;
		boolean hasEmulatorDetect = false;
		boolean hasFridaDetect = false;
		boolean hasXposedDetect = false;

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
			if (code == null || code.isEmpty() || !INTEGRITY_MARKER.matcher(code).find()) {
				continue;
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
						if ("runtime_signature_verify".equals(r.kind)) {
							hasSignatureVerify = true;
						}
						if ("dex_crc_check".equals(r.kind)) {
							hasDexCrc = true;
						}
						if ("debugger_detect".equals(r.kind)) {
							hasDebuggerDetect = true;
						}
						if ("emulator_detect".equals(r.kind)) {
							hasEmulatorDetect = true;
						}
						if ("frida_detect".equals(r.kind)) {
							hasFridaDetect = true;
						}
						if ("xposed_detect".equals(r.kind)) {
							hasXposedDetect = true;
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
		data.put("hasSignatureVerify", hasSignatureVerify);
		data.put("hasDexCrc", hasDexCrc);
		data.put("hasDebuggerDetect", hasDebuggerDetect);
		data.put("hasEmulatorDetect", hasEmulatorDetect);
		data.put("hasFridaDetect", hasFridaDetect);
		data.put("hasXposedDetect", hasXposedDetect);
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
		return "runtime-integrity-scan";
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
