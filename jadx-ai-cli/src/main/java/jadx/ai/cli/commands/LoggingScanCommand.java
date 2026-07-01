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
 * Scans decompiled code for sensitive data written to logs — MASVS MSTG-STORAGE-3. On a rooted or
 * pre-API-26 device, and to any app holding {@code READ_LOGS}, {@code Logcat} is readable; a
 * password, token, or session id printed there is a real leak, and one no other scanner here covers.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detection, per source line, is a logging sink whose message looks sensitive:
 * <ul>
 *   <li><b>Sink</b> — {@code Log.v/d/i/w/e/wtf(...)}, {@code System.out/err.print(ln)?(...)},
 *       {@code printStackTrace(...)}, or a common logger ({@code Timber.}, {@code Logger.},
 *       {@code Slf4j}-style {@code log.}).</li>
 *   <li><b>Sensitivity</b> — the line mentions a sensitive keyword ({@code password}, {@code passwd},
 *       {@code token}, {@code secret}, {@code apikey}/{@code api_key}, {@code privatekey},
 *       {@code credential}, {@code session}, {@code cookie}, {@code jwt}, {@code pin}, {@code ssn},
 *       {@code creditcard}/{@code cardnumber}, {@code cvv}, {@code auth}) — high; or it logs a
 *       known device identifier getter ({@code getDeviceId}, {@code getImei}, {@code getSubscriberId},
 *       {@code getSimSerialNumber}, {@code getMacAddress}, {@code getAndroidId},
 *       {@code Build.getSerial()} / {@code Build.SERIAL}) — medium (PII).</li>
 *   <li>A {@code printStackTrace()} with no sensitivity match — low (information disclosure / noise,
 *       should use a logging framework gated by {@code BuildConfig.DEBUG}).</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, logCallTotal,
 * truncated}}, where {@code logCallTotal} is every logging-sink call seen (sensitive or not) — a
 * cheap proxy for how chatty the app is, useful when triaging a release build that should be silent.
 */
@Command(name = "logging-scan",
		description = "Scan code for sensitive data in logs (Log.*/System.out/printStackTrace with passwords, tokens, PII)")
public class LoggingScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	private static final Pattern LOG_SINK = Pattern.compile(
			"\\bLog\\.(v|d|i|w|e|wtf)\\s*\\(|System\\.(out|err)\\.print(ln)?\\s*\\(|\\.printStackTrace\\s*\\(|\\bTimber\\.[a-z]+\\s*\\(|\\bLogger\\.[a-z]+\\s*\\(");

	private static final Pattern STACK_TRACE = Pattern.compile("\\.printStackTrace\\s*\\(");

	// Case-insensitive sensitive keywords; \b-ish boundaries via char-class to catch camelCase too.
	private static final Pattern SENSITIVE = Pattern.compile(
			"(?i)(password|passwd|secret|api[_-]?key|private[_-]?key|credential|session|cookie|\\bjwt\\b|\\btoken\\b|\\bpin\\b|\\bssn\\b|credit[_-]?card|card[_-]?number|\\bcvv\\b|auth(oriz|entic)|access[_-]?token|refresh[_-]?token|bearer)");

	/**
	 * Device-identifier getters whose value logged to logcat is PII. Includes
	 * {@code Build.getSerial()} (the API 26+ replacement for the deprecated {@code Build.SERIAL}
	 * field) — both are persistent device identifiers that {@code insecure-api-scan} also flags.
	 * {@code Build\.getSerial} is not matched by any pre-existing term here, so a
	 * {@code Log.d(TAG, Build.getSerial())} line was silently missed. Package-private so a test can
	 * assert the modern API form is not missed.
	 */
	static final String PII_GETTER_REGEX =
			"getDeviceId\\s*\\(|getImei\\s*\\(|getSubscriberId\\s*\\(|getSimSerialNumber\\s*\\(|"
					+ "getMacAddress\\s*\\(|getAndroidId\\s*\\(|getLine1Number\\s*\\(|"
					+ "Build\\.getSerial\\s*\\(|Build\\.SERIAL";

	private static final Pattern PII_GETTER = Pattern.compile(PII_GETTER_REGEX);

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
		int logCallTotal = 0;

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
				if (!LOG_SINK.matcher(line).find()) {
					continue;
				}
				logCallTotal++;
				int ln = i + 1;

				if (SENSITIVE.matcher(line).find()) {
					findings.add(finding(fullName, ln, "sensitive_log", "high",
							"Logging sink with a sensitive keyword — secrets/credentials written to logcat are readable on rooted/old devices and by READ_LOGS holders"));
				} else if (PII_GETTER.matcher(line).find()) {
					findings.add(finding(fullName, ln, "pii_log", "medium",
							"Logging a device identifier (IMEI/Android ID/MAC/...) — persistent PII in logs"));
				} else if (STACK_TRACE.matcher(line).find()) {
					findings.add(finding(fullName, ln, "stacktrace_log", "low",
							"printStackTrace() — information disclosure / noise in release builds; use a framework gated by BuildConfig.DEBUG"));
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("logCallTotal", logCallTotal);
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
		return "logging-scan";
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
