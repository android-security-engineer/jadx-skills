package jadx.ai.cli.commands;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.ExternalTool;
import jadx.api.JadxDecompiler;

/**
 * Adapter around the external <a href="https://frida.re">Frida</a> toolchain — the runtime,
 * dynamic-instrumentation counterpart to {@link HookCommand}, which only emits Frida snippets
 * statically. Where {@code hook} writes a script for you to run by hand, {@code frida} actually
 * drives the on-device agent: enumerate devices/processes, spawn a package with an injected
 * script, attach to a running process, or run {@code frida-trace}. Completes the external-adapter
 * trio alongside {@link ApktoolCommand} and {@link AdbCommand}, on the same
 * {@link AbstractExternalCommand}/{@link ExternalTool} template (no decompiler, per-binary PATH
 * resolution with {@code JADX_AI_<TOOL>_PATH} overrides, timeout, graceful
 * {@code ToolNotInstalled}).
 *
 * <p>Frida ships as several sibling executables; each action targets the right one and degrades
 * independently when only some are installed:
 * <ul>
 *   <li>{@code list-devices} → {@code frida-ls-devices}</li>
 *   <li>{@code ps} → {@code frida-ps} (default {@code -U}; pass {@code --args "-Uai"} for installed apps)</li>
 *   <li>{@code version} → {@code frida --version}</li>
 *   <li>{@code run-script} → {@code frida -q -l <script>} spawning {@code -f <package>} or attaching {@code -n <name>}</li>
 *   <li>{@code trace} → {@code frida-trace} (spawn {@code -f <package>} or attach {@code -n <name>}) with patterns from {@code --args}</li>
 * </ul>
 *
 * Usage:
 *   jadx-ai frida --action list-devices
 *   jadx-ai frida --action ps --args "-Uai"
 *   jadx-ai frida --action run-script --package com.example.app --script hook.js
 *   jadx-ai frida --action run-script --name com.example.app --script hook.js
 *   jadx-ai frida --action trace --package com.example.app --args "-i open -i read"
 */
@Command(name = "frida", description = "Drive the external Frida toolchain (list-devices/ps/version/run-script/trace)")
public class FridaCommand extends AbstractExternalCommand {

	@Option(names = { "--action" }, description = "Action: list-devices, ps, version, run-script, trace",
			defaultValue = "list-devices")
	protected String action;

	@Option(names = { "--package", "-p" }, description = "Target package to spawn (frida -f); run-script/trace")
	protected String packageName;

	@Option(names = { "--name", "-n" }, description = "Running process name to attach to (frida -n); run-script/trace")
	protected String processName;

	@Option(names = { "--script", "-l" }, description = "Frida JavaScript agent to load (run-script)")
	protected File script;

	@Option(names = { "--device", "-D" }, description = "Frida device id (frida -D <id>); default USB (-U)")
	protected String device;

	@Option(names = { "--args" }, description = "Extra arguments (e.g. frida-ps flags, frida-trace patterns), as one string")
	protected String argsOption;

	@Option(names = { "--timeout" }, description = "Tool timeout in milliseconds", defaultValue = "60000")
	protected long timeoutMs = 60000;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.get("action") != null) {
			this.action = (String) args.get("action");
		}
		if (args.get("package") != null) {
			this.packageName = (String) args.get("package");
		}
		if (args.get("name") != null) {
			this.processName = (String) args.get("name");
		}
		if (args.get("script") != null) {
			this.script = new File((String) args.get("script"));
		}
		if (args.get("device") != null) {
			this.device = (String) args.get("device");
		}
		if (args.get("args") != null) {
			this.argsOption = (String) args.get("args");
		}
		if (args.get("timeout") != null) {
			this.timeoutMs = ((Number) args.get("timeout")).longValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		String act = action == null ? "list-devices" : action.toLowerCase(Locale.ROOT);
		switch (act) {
			case "list-devices": {
				List<String> toolArgs = new ArrayList<>();
				addExtra(toolArgs);
				return annotate(ExternalTool.runOrToolMissing("frida-ls-devices", toolArgs, timeoutMs, null), act);
			}
			case "ps": {
				List<String> toolArgs = new ArrayList<>();
				if (argsOption == null || argsOption.isBlank()) {
					// Default to the USB device's running processes.
					toolArgs.add("-U");
				} else {
					addExtra(toolArgs);
				}
				return annotate(ExternalTool.runOrToolMissing("frida-ps", toolArgs, timeoutMs, null), act);
			}
			case "version": {
				List<String> toolArgs = new ArrayList<>();
				toolArgs.add("--version");
				return annotate(ExternalTool.runOrToolMissing("frida", toolArgs, timeoutMs, null), act);
			}
			case "run-script":
				return runScript();
			case "trace":
				return trace();
			default:
				return JsonOutput.error("InvalidAction",
						"Unknown action: " + action
								+ ". Use: list-devices, ps, version, run-script, trace.");
		}
	}

	/** {@code frida -q -l <script>} spawning {@code -f <package>} or attaching {@code -n <name>}. */
	private Object runScript() {
		if (script == null) {
			return JsonOutput.error("MissingInput", "frida run-script requires --script <agent.js>");
		}
		if (!script.isFile()) {
			return JsonOutput.error("MissingInput", "Frida script not found: " + script.getAbsolutePath());
		}
		if (packageName == null && processName == null) {
			return JsonOutput.error("MissingInput",
					"frida run-script requires a target: --package <pkg> (spawn) or --name <process> (attach)");
		}
		List<String> toolArgs = new ArrayList<>();
		addTarget(toolArgs);
		toolArgs.add("-q"); // quiet: no REPL banner, suitable for one-shot capture
		toolArgs.add("-l");
		toolArgs.add(script.getAbsolutePath());
		addExtra(toolArgs);
		Object result = ExternalTool.runOrToolMissing("frida", toolArgs, timeoutMs, null);
		Object annotated = annotate(result, "run-script");
		attach(annotated, "script", script.getAbsolutePath());
		return annotated;
	}

	/** {@code frida-trace} against a spawned {@code -f <package>} or attached {@code -n <name>}. */
	private Object trace() {
		if (packageName == null && processName == null) {
			return JsonOutput.error("MissingInput",
					"frida trace requires a target: --package <pkg> (spawn) or --name <process> (attach)");
		}
		List<String> toolArgs = new ArrayList<>();
		addTarget(toolArgs);
		// Trace patterns (e.g. "-i open -j 'com.example.*!*'") come through --args.
		addExtra(toolArgs);
		return annotate(ExternalTool.runOrToolMissing("frida-trace", toolArgs, timeoutMs, null), "trace");
	}

	/** Append device selector + spawn/attach target shared by run-script and trace. */
	private void addTarget(List<String> toolArgs) {
		if (device != null && !device.isBlank()) {
			toolArgs.add("-D");
			toolArgs.add(device);
		} else {
			toolArgs.add("-U");
		}
		if (packageName != null && !packageName.isBlank()) {
			toolArgs.add("-f");
			toolArgs.add(packageName);
		} else if (processName != null && !processName.isBlank()) {
			toolArgs.add("-n");
			toolArgs.add(processName);
		}
	}

	private void addExtra(List<String> toolArgs) {
		String extra = argsOption;
		if (extra != null && !extra.isBlank()) {
			// Split on whitespace — sufficient for typical frida flag strings.
			for (String part : extra.trim().split("\\s+")) {
				toolArgs.add(part);
			}
		}
	}

	private Object annotate(Object result, String act) {
		attach(result, "action", act);
		return result;
	}

	@SuppressWarnings("unchecked")
	private void attach(Object result, String key, Object value) {
		if (result instanceof JsonOutput) {
			JsonOutput out = (JsonOutput) result;
			if (out.isSuccess() && out.getData() instanceof Map) {
				((Map<String, Object>) out.getData()).put(key, value);
			}
		}
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("action", action);
		if (packageName != null) {
			args.put("package", packageName);
		}
		if (processName != null) {
			args.put("name", processName);
		}
		if (script != null) {
			args.put("script", script.getAbsolutePath());
		}
		if (device != null) {
			args.put("device", device);
		}
		if (argsOption != null) {
			args.put("args", argsOption);
		}
		args.put("timeout", timeoutMs);
		return args;
	}
}
