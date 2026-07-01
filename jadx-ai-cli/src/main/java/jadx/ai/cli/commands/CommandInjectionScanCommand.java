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
 * Scans decompiled code for OS command injection and unsafe native-process execution — MASVS
 * MSTG-CODE, the sibling sink to {@link SqlInjectionScanCommand} (a query string injected vs a shell
 * command injected). Native: reads jadx's parsed model, no external tool.
 *
 * <p>The vulnerability is a process launched from a command line assembled by string concatenation
 * with untrusted input. Detections, per source line:
 * <ul>
 *   <li>{@code Runtime.getRuntime().exec(...)} / {@code new ProcessBuilder(...)} whose argument is
 *       built with string concatenation — high (attacker controls the command/args)</li>
 *   <li>execution of a shell ({@code "sh"}, {@code "/bin/sh"}, {@code "sh", "-c"}, {@code "bash"})
 *       — high when concatenated, medium otherwise (shell interpretation amplifies injection)</li>
 *   <li>{@code exec}/{@code ProcessBuilder} with a static, non-concatenated argument — info (a
 *       process is still spawned; worth a look but not injectable)</li>
 *   <li>a {@code "su"} / {@code "/system/xbin/su"} invocation — info (root-shell attempt; common in
 *       both malware and legitimate root-aware apps, flagged for triage)</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * truncated}}.
 */
@Command(name = "command-injection-scan",
		description = "Scan code for OS command injection (Runtime.exec/ProcessBuilder built via string concatenation, shell -c, su)")
public class CommandInjectionScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** A class that spawns processes at all — scope the scan here to keep signal high. */
	private static final Pattern EXEC_MARKER =
			Pattern.compile("Runtime|ProcessBuilder|\\.exec\\s*\\(|getRuntime\\s*\\(");

	/** Two fragments joined by {@code +} — the concatenation that makes a command injectable. */
	private static final Pattern CONCAT = Pattern.compile("\"\\s*\\+|\\+\\s*\"");

	private static final Pattern EXEC = Pattern.compile("\\.exec\\s*\\(");
	private static final Pattern PROCESS_BUILDER = Pattern.compile("new\\s+ProcessBuilder\\s*\\(|ProcessBuilder\\s*\\(");
	private static final Pattern SHELL = Pattern.compile(
			"\"(/system/bin/|/bin/)?(sh|bash)\"|\"-c\"|\"/system/bin/sh\"");
	private static final Pattern SU = Pattern.compile("\"su\"|\"/system/(xbin|bin)/su\"|\"which\"\\s*,\\s*\"su\"");

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
			if (code == null || code.isEmpty() || !EXEC_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;
				boolean isExec = EXEC.matcher(line).find();
				boolean isPb = PROCESS_BUILDER.matcher(line).find();
				if (!isExec && !isPb) {
					continue;
				}
				boolean concat = CONCAT.matcher(line).find();
				boolean shell = SHELL.matcher(line).find();
				boolean su = SU.matcher(line).find();

				Map<String, Object> f;
				if (concat) {
					String sink = isPb ? "ProcessBuilder" : "Runtime.exec";
					f = finding(fullName, ln, "command_injection", "high",
							sink + " command built with string concatenation"
									+ (shell ? " through a shell (-c) — direct OS command injection" : " — validate/escape all untrusted input"));
				} else if (su) {
					f = finding(fullName, ln, "root_shell", "info",
							"Invokes 'su' — root-shell execution (triage: malware or root-aware app)");
				} else if (shell) {
					f = finding(fullName, ln, "shell_exec", "medium",
							"Spawns a shell interpreter (sh/bash -c) — any later concatenation here is injectable");
				} else {
					f = finding(fullName, ln, "process_exec", "info",
							(isPb ? "ProcessBuilder" : "Runtime.exec") + " with a static command — a process is spawned, verify the args are trusted");
				}

				if ("high".equals(f.get("severity"))) {
					highSeverityCount++;
				}
				findings.add(f);
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
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
		return "command-injection-scan";
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
