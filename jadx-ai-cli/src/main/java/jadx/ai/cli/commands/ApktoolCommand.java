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
 * Adapter around the external {@code apktool} binary for full resource (un)packing — the one
 * capability jadx itself does not provide (it decompiles code, apktool round-trips smali +
 * decoded resources). This is the template for future external-tool adapters (frida, adb):
 * it loads no decompiler, locates the binary via {@link ExternalTool} (PATH or
 * {@code JADX_AI_APKTOOL_PATH}), runs it with a timeout, and degrades to a {@code ToolNotInstalled}
 * error when the binary is absent.
 *
 * Usage:
 *   jadx-ai apktool --action decode --apk app.apk --out /tmp/app
 *   jadx-ai apktool --action build  --apk /tmp/app --out rebuilt.apk
 */
@Command(name = "apktool", description = "Decode or rebuild an APK with the external apktool binary")
public class ApktoolCommand extends AbstractExternalCommand {

	@Option(names = { "--action" }, description = "Action: decode, build", defaultValue = "decode")
	protected String action;

	@Option(names = { "--apk" }, description = "Input APK (decode) or input directory (build); "
			+ "falls back to the positional input file")
	protected File apk;

	@Option(names = { "--out", "-o" }, description = "Output directory (decode) or output APK (build)")
	protected File out;

	@Option(names = { "--frame-path" }, description = "Framework files directory (apktool --frame-path)")
	protected File framePath;

	@Option(names = { "--no-res" }, description = "decode: skip resources (apktool --no-res)")
	protected boolean noRes;

	@Option(names = { "--no-src" }, description = "decode: skip sources/smali (apktool --no-src)")
	protected boolean noSrc;

	@Option(names = { "--timeout" }, description = "Tool timeout in milliseconds", defaultValue = "120000")
	protected long timeoutMs = 120000;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.get("action") != null) {
			this.action = (String) args.get("action");
		}
		if (args.get("apk") != null) {
			this.apk = new File((String) args.get("apk"));
		}
		if (args.get("out") != null) {
			this.out = new File((String) args.get("out"));
		}
		if (args.get("framePath") != null) {
			this.framePath = new File((String) args.get("framePath"));
		}
		if (args.containsKey("noRes")) {
			this.noRes = Boolean.TRUE.equals(args.get("noRes"));
		}
		if (args.containsKey("noSrc")) {
			this.noSrc = Boolean.TRUE.equals(args.get("noSrc"));
		}
		if (args.get("timeout") != null) {
			this.timeoutMs = ((Number) args.get("timeout")).longValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		File input = apk != null ? apk : inputFile;
		String act = action == null ? "decode" : action.toLowerCase(Locale.ROOT);

		List<String> toolArgs = new ArrayList<>();
		switch (act) {
			case "decode":
			case "d":
				if (input == null) {
					return JsonOutput.error("MissingInput",
							"apktool decode requires --apk <file> (or a positional APK path)");
				}
				toolArgs.add("d");
				toolArgs.add(input.getAbsolutePath());
				if (out != null) {
					toolArgs.add("-o");
					toolArgs.add(out.getAbsolutePath());
				}
				if (noRes) {
					toolArgs.add("--no-res");
				}
				if (noSrc) {
					toolArgs.add("--no-src");
				}
				toolArgs.add("-f"); // force overwrite of the output dir
				break;
			case "build":
			case "b":
				if (input == null) {
					return JsonOutput.error("MissingInput",
							"apktool build requires --apk <decoded-dir> (or a positional dir path)");
				}
				toolArgs.add("b");
				toolArgs.add(input.getAbsolutePath());
				if (out != null) {
					toolArgs.add("-o");
					toolArgs.add(out.getAbsolutePath());
				}
				break;
			default:
				return JsonOutput.error("InvalidAction",
						"Unknown action: " + action + ". Use: decode, build. "
								+ "To sign an APK use 'jadx-ai signature' / apksigner.");
		}

		if (framePath != null) {
			toolArgs.add("--frame-path");
			toolArgs.add(framePath.getAbsolutePath());
		}

		Object result = ExternalTool.runOrToolMissing("apktool", toolArgs, timeoutMs, null);
		return annotate(result, act, input);
	}

	/** Attach the action/input context to a successful tool result for easier consumption. */
	@SuppressWarnings("unchecked")
	private Object annotate(Object result, String act, File input) {
		if (result instanceof JsonOutput) {
			JsonOutput out2 = (JsonOutput) result;
			if (out2.isSuccess() && out2.getData() instanceof Map) {
				Map<String, Object> dataMap = (Map<String, Object>) out2.getData();
				dataMap.put("action", act);
				if (input != null) {
					dataMap.put("input", input.getAbsolutePath());
				}
				if (out != null) {
					dataMap.put("output", out.getAbsolutePath());
				}
			}
		}
		return result;
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("action", action);
		if (apk != null) {
			args.put("apk", apk.getAbsolutePath());
		}
		if (out != null) {
			args.put("out", out.getAbsolutePath());
		}
		if (framePath != null) {
			args.put("framePath", framePath.getAbsolutePath());
		}
		args.put("noRes", noRes);
		args.put("noSrc", noSrc);
		args.put("timeout", timeoutMs);
		return args;
	}
}
