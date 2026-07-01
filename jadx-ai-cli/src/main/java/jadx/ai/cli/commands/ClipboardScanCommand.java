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
 * Scans decompiled code for risky clipboard usage — MASVS MSTG-STORAGE-2. Native: reads jadx's
 * parsed model, no external tool.
 *
 * <p>The Android clipboard is a process-global, cross-app channel. Until Android 12 any app could
 * read {@code getPrimaryClip()} silently; a registered {@code OnPrimaryClipChangedListener} can sniff
 * whatever the user copies (passwords from a manager, OTPs, card numbers). The line-level rules:
 * <ul>
 *   <li><b>Write</b> — {@code setPrimaryClip(} / {@code setText(} on a clipboard manager. Medium if
 *       the line also mentions a sensitive keyword (a secret placed on the global clipboard), else
 *       low.</li>
 *   <li><b>Read</b> — {@code getPrimaryClip(} / {@code getPrimaryClipDescription(} / {@code getText(}
 *       on the clipboard. Low (possible sniffing / clipboard ingestion).</li>
 *   <li><b>Monitor</b> — {@code addPrimaryClipChangedListener(} or implementing
 *       {@code OnPrimaryClipChangedListener}: continuous clipboard surveillance. Medium.</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, sensitiveWrites,
 * monitorsClipboard, truncated}}.
 */
@Command(name = "clipboard-scan",
		description = "Scan code for risky clipboard usage (sensitive data copied to the global clipboard, clipboard read/monitoring sniffing)")
public class ClipboardScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Class-level gate: only classes that touch the clipboard at all. */
	private static final Pattern CLIPBOARD_MARKER = Pattern.compile(
			"ClipboardManager|ClipData|CLIPBOARD_SERVICE|getSystemService\\s*\\(\\s*\"clipboard\"|setPrimaryClip|getPrimaryClip|PrimaryClipChanged");

	private static final Pattern WRITE = Pattern.compile("setPrimaryClip\\s*\\(|\\.setText\\s*\\(");
	private static final Pattern READ = Pattern.compile(
			"getPrimaryClip\\s*\\(|getPrimaryClipDescription\\s*\\(|getItemAt\\s*\\(|\\.getText\\s*\\(\\s*\\)|coerceToText\\s*\\(");
	private static final Pattern MONITOR = Pattern.compile(
			"addPrimaryClipChangedListener\\s*\\(|OnPrimaryClipChangedListener|onPrimaryClipChanged\\s*\\(");

	private static final Pattern SENSITIVE = Pattern.compile(
			"(?i)(password|passwd|secret|api[_-]?key|private[_-]?key|credential|\\btoken\\b|\\bpin\\b|\\bcvv\\b|credit[_-]?card|card[_-]?number|\\botp\\b|seed[_-]?phrase|mnemonic|\\bbearer\\b|account[_-]?number|iban)");

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
		int sensitiveWrites = 0;
		boolean monitorsClipboard = false;

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
			if (code == null || code.isEmpty() || !CLIPBOARD_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;

				if (MONITOR.matcher(line).find()) {
					findings.add(finding(fullName, ln, "clipboard_monitor", "medium",
							"Clipboard change listener — can silently sniff anything the user copies (passwords, OTPs, card numbers)"));
					monitorsClipboard = true;
				} else if (WRITE.matcher(line).find()) {
					boolean sensitive = SENSITIVE.matcher(line).find();
					if (sensitive) {
						findings.add(finding(fullName, ln, "sensitive_clipboard_write", "medium",
								"Sensitive value copied to the process-global clipboard — readable by any app (pre-Android 12 silently)"));
						sensitiveWrites++;
					} else {
						findings.add(finding(fullName, ln, "clipboard_write", "low",
								"Data written to the global clipboard — verify it is not sensitive"));
					}
				} else if (READ.matcher(line).find()) {
					findings.add(finding(fullName, ln, "clipboard_read", "low",
							"Clipboard read — possible ingestion/sniffing of data copied from other apps"));
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("sensitiveWrites", sensitiveWrites);
		data.put("monitorsClipboard", monitorsClipboard);
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
		return "clipboard-scan";
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
