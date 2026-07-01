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
 * Subprocess/command-execution scanner — MASVS MSTG-CODE-7.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects subprocess creation patterns: Runtime.exec, ProcessBuilder,
 * shell command execution with user input, and su/do-root execution.
 * Distinct from {@code command-injection-scan} (OS command injection data-flow
 * tracing) — this scanner focuses on <b>process-creation patterns and
 * their security posture</b>, not data-flow taint tracking.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code runtime_exec_user_input} — Runtime.exec() with string concatenation
 *       or variable — classic command injection vector</li>
 *   <li>{@code processbuilder_user_input} — ProcessBuilder with variable arguments
 *       — command injection if args are user-controlled</li>
 *   <li>{@code su_command} — "su" or "sudo" in command string — attempts to
 *       execute with elevated privileges; may indicate root requirements</li>
 *   <li>{@code shell_execution} — "sh -c" or "bash -c" pattern — shell
 *       interpretation of command enables metacharacter injection</li>
 *   <li>{@code runtime_exec} — Runtime.exec() with string literal — inventory;
 *       fixed commands are safe but worth auditing</li>
 *   <li>{@code processbuilder} — ProcessBuilder usage — inventory; safer than
 *       Runtime.exec but still needs input validation</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasSuCommand, hasUserInputExec, truncated}}.
 */
@Command(name = "subprocess-scan",
		description = "Detect subprocess/command execution security issues (MASVS MSTG-CODE-7): Runtime.exec with user input, ProcessBuilder with variables, su/sudo commands, shell execution. Distinct from command-injection-scan (data-flow taint tracking)")
public class SubprocessScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with subprocess markers. */
	private static final Pattern SUBPROC_MARKER = Pattern.compile(
			"Runtime\\.exec|ProcessBuilder|Process\\s|Runtime\\.getRuntime|"
					+ "su\\b|sudo\\b|sh\\s+-c|bash\\s+-c");

	private static final Pattern RUNTIME_EXEC_USER = Pattern.compile(
			"Runtime\\.exec\\s*\\(.*\\+|Runtime\\.exec\\s*\\(.*String|"
					+ "getRuntime\\(\\)\\.exec\\s*\\(.*\\+");
	private static final Pattern PROCESSBUILDER_USER = Pattern.compile(
			"ProcessBuilder\\s*\\(.*\\+|ProcessBuilder\\s*\\(.*String|"
					+ "ProcessBuilder\\s*\\(\\s*Arrays\\.asList|"
					+ "new\\s+ProcessBuilder\\s*\\([^)]*\\+");
	private static final Pattern SU_COMMAND = Pattern.compile(
			"\"su\"|\"sudo\"|\\bsu\\b.*-c|\\bsudo\\b.*-c|"
					+ "exec\\s*\\(\\s*\"su|Runtime.*\"su\"|"
					+ "ProcessBuilder.*\"su\"|\"/system/bin/su\"|"
					+ "\"/system/xbin/su\"");
	private static final Pattern SHELL_EXECUTION = Pattern.compile(
			"\"sh\"\\s*,\\s*\"-c\"|\"bash\"\\s*,\\s*\"-c\"|"
					+ "sh\\s+-c|bash\\s+-c|"
					+ "\"/bin/sh\"|\"/bin/bash\"|"
					+ "ProcessBuilder.*sh.*-c");
	private static final Pattern RUNTIME_EXEC_LITERAL = Pattern.compile(
			"Runtime\\.exec\\s*\\(\\s*\"|getRuntime\\(\\)\\.exec\\s*\\(\\s*\"");
	private static final Pattern PROCESSBUILDER_LITERAL = Pattern.compile(
			"new\\s+ProcessBuilder\\s*\\(");

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
		new Rule(RUNTIME_EXEC_USER, "runtime_exec_user_input", "high",
				"Runtime.exec() with string concatenation/variable — classic command "
						+ "injection vector; use ProcessBuilder with separate arguments instead"),
		new Rule(PROCESSBUILDER_USER, "processbuilder_user_input", "high",
				"ProcessBuilder with variable/concatenated arguments — command injection "
						+ "if args are user-controlled; validate and sanitize all inputs"),
		new Rule(SU_COMMAND, "su_command", "high",
				"'su'/'sudo' command execution — attempts to elevate privileges; "
						+ "indicates root requirement or privilege escalation attempt"),
		new Rule(SHELL_EXECUTION, "shell_execution", "high",
				"Shell execution via 'sh -c'/'bash -c' — shell interprets metacharacters; "
						+ "enables command injection through special characters; use "
						+ "ProcessBuilder with separate arguments"),
		new Rule(RUNTIME_EXEC_LITERAL, "runtime_exec", "info",
				"Runtime.exec() with literal command — fixed command is safe from injection "
						+ "but worth auditing for unintended operations"),
		new Rule(PROCESSBUILDER_LITERAL, "processbuilder", "info",
				"ProcessBuilder usage — safer than Runtime.exec for argument separation; "
						+ "still ensure all dynamic inputs are validated"),
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
		boolean hasSuCommand = false;
		boolean hasUserInputExec = false;

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
			if (code == null || code.isEmpty() || !SUBPROC_MARKER.matcher(code).find()) {
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
						if ("su_command".equals(r.kind)) {
							hasSuCommand = true;
						}
						if ("runtime_exec_user_input".equals(r.kind) || "processbuilder_user_input".equals(r.kind)) {
							hasUserInputExec = true;
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
		data.put("hasSuCommand", hasSuCommand);
		data.put("hasUserInputExec", hasUserInputExec);
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
		return "subprocess-scan";
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
