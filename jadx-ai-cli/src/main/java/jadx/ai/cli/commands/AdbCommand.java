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
 * Adapter around the external {@code adb} binary — the bridge from static analysis to a live
 * device/emulator, absorbing the device-interaction half of the studied RE tooling (install a
 * rebuilt APK, pull an installed package's base.apk for decompilation, read logcat, run a shell
 * command). Built on the same {@link AbstractExternalCommand}/{@link ExternalTool} template as
 * {@link ApktoolCommand}: loads no decompiler, locates {@code adb} on PATH (or via
 * {@code JADX_AI_ADB_PATH}), runs with a timeout, and degrades to {@code ToolNotInstalled} when
 * the binary is absent.
 *
 * Usage:
 *   jadx-ai adb --action devices
 *   jadx-ai adb --action install --apk app.apk
 *   jadx-ai adb --action pull-apk --package com.example.app --out /tmp/base.apk
 *   jadx-ai adb --action logcat --args "-d -t 200"
 *   jadx-ai adb --action shell --args "pm list packages -3"
 */
@Command(name = "adb", description = "Drive a device/emulator via the external adb binary (devices/install/pull-apk/logcat/shell)")
public class AdbCommand extends AbstractExternalCommand {

	@Option(names = { "--action" }, description = "Action: devices, install, uninstall, pull-apk, logcat, shell",
			defaultValue = "devices")
	protected String action;

	@Option(names = { "--serial", "-s" }, description = "Target device serial (adb -s); optional")
	protected String serial;

	@Option(names = { "--apk" }, description = "APK path (install); falls back to the positional input file")
	protected File apk;

	@Option(names = { "--package" }, description = "Package name (uninstall / pull-apk)")
	protected String packageName;

	@Option(names = { "--out", "-o" }, description = "Output APK path (pull-apk)")
	protected File out;

	@Option(names = { "--args" }, description = "Extra arguments for shell/logcat, as one string")
	protected String argsOption;

	@Option(names = { "--timeout" }, description = "Tool timeout in milliseconds", defaultValue = "60000")
	protected long timeoutMs = 60000;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.get("action") != null) {
			this.action = (String) args.get("action");
		}
		if (args.get("serial") != null) {
			this.serial = (String) args.get("serial");
		}
		if (args.get("apk") != null) {
			this.apk = new File((String) args.get("apk"));
		}
		if (args.get("package") != null) {
			this.packageName = (String) args.get("package");
		}
		if (args.get("out") != null) {
			this.out = new File((String) args.get("out"));
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
		String act = action == null ? "devices" : action.toLowerCase(Locale.ROOT);
		List<String> toolArgs = new ArrayList<>();
		if (serial != null && !serial.isBlank()) {
			toolArgs.add("-s");
			toolArgs.add(serial);
		}

		switch (act) {
			case "devices":
				toolArgs.add("devices");
				toolArgs.add("-l");
				break;
			case "install": {
				File input = apk != null ? apk : inputFile;
				if (input == null) {
					return JsonOutput.error("MissingInput",
							"adb install requires --apk <file> (or a positional APK path)");
				}
				toolArgs.add("install");
				toolArgs.add("-r");
				toolArgs.add(input.getAbsolutePath());
				break;
			}
			case "uninstall":
				if (packageName == null) {
					return JsonOutput.error("MissingInput", "adb uninstall requires --package <name>");
				}
				toolArgs.add("uninstall");
				toolArgs.add(packageName);
				break;
			case "pull-apk":
				// Resolve the installed base.apk path on-device, then pull it. Two-step because the
				// path is dynamic (/data/app/<pkg>-<hash>/base.apk).
				return pullApk();
			case "logcat":
				toolArgs.add("logcat");
				addExtra(toolArgs);
				break;
			case "shell":
				toolArgs.add("shell");
				addExtra(toolArgs);
				break;
			default:
				return JsonOutput.error("InvalidAction",
						"Unknown action: " + action + ". Use: devices, install, uninstall, pull-apk, logcat, shell.");
		}

		Object result = ExternalTool.runOrToolMissing("adb", toolArgs, timeoutMs, null);
		return annotate(result, act);
	}

	/** Resolve the on-device APK path via {@code pm path}, then {@code adb pull} it locally. */
	private Object pullApk() throws Exception {
		if (packageName == null) {
			return JsonOutput.error("MissingInput", "adb pull-apk requires --package <name>");
		}
		List<String> pathArgs = new ArrayList<>();
		if (serial != null && !serial.isBlank()) {
			pathArgs.add("-s");
			pathArgs.add(serial);
		}
		pathArgs.add("shell");
		pathArgs.add("pm");
		pathArgs.add("path");
		pathArgs.add(packageName);

		ExternalTool.Result pathRes = ExternalTool.run("adb", pathArgs, timeoutMs, null);
		if (!pathRes.ran) {
			return JsonOutput.error("ToolNotInstalled", "adb binary not found on PATH or JADX_AI_ADB_PATH");
		}
		if (pathRes.exitCode != 0 || pathRes.stdout == null || !pathRes.stdout.contains("package:")) {
			return JsonOutput.error("PackageNotFound",
					"Could not resolve APK path for " + packageName + ": "
							+ (pathRes.stderr == null ? pathRes.stdout : pathRes.stderr));
		}
		// `pm path` emits lines like "package:/data/app/.../base.apk"; take the first base.apk.
		String devicePath = null;
		for (String line : pathRes.stdout.split("\\R")) {
			line = line.trim();
			if (line.startsWith("package:")) {
				String p = line.substring("package:".length()).trim();
				if (p.endsWith("base.apk") || devicePath == null) {
					devicePath = p;
				}
			}
		}
		if (devicePath == null) {
			return JsonOutput.error("PackageNotFound", "No APK path parsed for " + packageName);
		}

		File target = out != null ? out : new File(packageName + ".apk");
		List<String> pullArgs = new ArrayList<>();
		if (serial != null && !serial.isBlank()) {
			pullArgs.add("-s");
			pullArgs.add(serial);
		}
		pullArgs.add("pull");
		pullArgs.add(devicePath);
		pullArgs.add(target.getAbsolutePath());

		Object result = ExternalTool.runOrToolMissing("adb", pullArgs, timeoutMs, null);
		Object annotated = annotate(result, "pull-apk");
		attach(annotated, "devicePath", devicePath);
		attach(annotated, "output", target.getAbsolutePath());
		return annotated;
	}

	private void addExtra(List<String> toolArgs) {
		String extra = argsOption;
		if (extra != null && !extra.isBlank()) {
			// Split on whitespace — sufficient for typical logcat/shell flag strings.
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
		if (serial != null) {
			args.put("serial", serial);
		}
		if (apk != null) {
			args.put("apk", apk.getAbsolutePath());
		}
		if (packageName != null) {
			args.put("package", packageName);
		}
		if (out != null) {
			args.put("out", out.getAbsolutePath());
		}
		if (argsOption != null) {
			args.put("args", argsOption);
		}
		args.put("timeout", timeoutMs);
		return args;
	}
}
