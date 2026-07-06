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
 * Scans for weak biometric authentication — MASVS MSTG-AUTH-1 / MSTG-AUTH-8. Native: reads jadx's
 * parsed model, no external tool.
 *
 * <p>The decisive question for biometric auth on Android is whether success is <em>cryptographically
 * bound</em>: an {@code authenticate(CryptoObject)} call gates a Keystore key whose use required user
 * authentication, so a "yes" cannot be forged. An {@code authenticate()} with <b>no</b> CryptoObject
 * is a bare boolean — the success callback can be reached by a Frida hook or a tampered build, the
 * classic "event-bound" bypass. This scanner works per class so it can see whether a CryptoObject is
 * constructed anywhere in the same class that calls {@code authenticate}:
 * <ul>
 *   <li><b>biometric_no_crypto</b> (high) — a class calls {@code BiometricPrompt.authenticate}/
 *       {@code FingerprintManager.authenticate} but constructs no {@code CryptoObject} — result is
 *       not key-bound, bypassable.</li>
 *   <li><b>deprecated_fingerprint</b> (medium) — uses {@code FingerprintManager} (API&lt;28,
 *       deprecated) instead of {@code BiometricPrompt}.</li>
 *   <li><b>weak_biometric_class</b> (low) — allows {@code BIOMETRIC_WEAK} /
 *       {@code setDeviceCredentialAllowed(true)} / {@code DEVICE_CREDENTIAL}, lowering the bar to a
 *       Class-2 sensor or device PIN.</li>
 *   <li><b>biometric_crypto_ok</b> (info) — an {@code authenticate(CryptoObject)} is present (good).</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * usesCryptoObject, truncated}}.
 */
@Command(name = "biometric-scan",
		description = "Scan for weak biometric auth (MASVS MSTG-AUTH): BiometricPrompt/FingerprintManager.authenticate without a CryptoObject (bypassable), deprecated FingerprintManager, weak/credential fallback")
public class BiometricScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Class-level gate: only classes that do biometric auth at all. */
	private static final Pattern BIOMETRIC_MARKER = Pattern.compile(
			"BiometricPrompt|FingerprintManager|BiometricManager|androidx\\.biometric|KeyguardManager");

	private static final Pattern AUTHENTICATE = Pattern.compile("\\.authenticate\\s*\\(");
	private static final Pattern CRYPTO_OBJECT = Pattern.compile(
			"CryptoObject|BiometricPrompt\\.CryptoObject|FingerprintManager\\.CryptoObject");
	private static final Pattern DEPRECATED_FP = Pattern.compile(
			"FingerprintManager(?!\\.CryptoObject)|FingerprintManagerCompat");
	private static final Pattern WEAK_CLASS = Pattern.compile(
			"BIOMETRIC_WEAK|setDeviceCredentialAllowed\\s*\\(\\s*true|DEVICE_CREDENTIAL|Authenticators\\.DEVICE_CREDENTIAL");

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
		boolean usesCryptoObject = false;

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
			if (code == null || code.isEmpty() || !BIOMETRIC_MARKER.matcher(code).find()) {
				continue;
			}

			// Whole-class view: is a CryptoObject bound anywhere in the class that authenticates?
			boolean classBindsCrypto = CRYPTO_OBJECT.matcher(code).find();
			if (classBindsCrypto) {
				usesCryptoObject = true;
			}

			String[] lines = code.split("\n", -1);
			boolean reportedNoCrypto = false;
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;

				if (AUTHENTICATE.matcher(line).find() && !classBindsCrypto && !reportedNoCrypto) {
					findings.add(finding(fullName, ln, "biometric_no_crypto", "high",
							"Biometric authenticate() with no CryptoObject in this class — success is a bare boolean, reachable by a Frida hook / tampered build (event-bound bypass). Gate a Keystore key with setUserAuthenticationRequired(true) and pass its CryptoObject"));
					highSeverityCount++;
					reportedNoCrypto = true; // one per class to avoid noise
					continue;
				}
				if (WEAK_CLASS.matcher(line).find()) {
					findings.add(finding(fullName, ln, "weak_biometric_class", "low",
							"Weak biometric / device-credential fallback allowed (BIOMETRIC_WEAK / DEVICE_CREDENTIAL) — lowers assurance to a Class-2 sensor or device PIN"));
				} else if (DEPRECATED_FP.matcher(line).find() && line.contains("FingerprintManager")) {
					findings.add(finding(fullName, ln, "deprecated_fingerprint", "medium",
							"Deprecated FingerprintManager (API<28) — migrate to androidx.biometric BiometricPrompt"));
				}
			}

			if (classBindsCrypto) {
				findings.add(finding(fullName, 0, "biometric_crypto_ok", "info",
						"CryptoObject-bound biometric auth present in this class (good — success is key-bound)"));
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("usesCryptoObject", usesCryptoObject);
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
		return "biometric-scan";
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
