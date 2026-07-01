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
 * Scans Android Keystore key-protection posture — MASVS MSTG-CRYPTO-1 / MSTG-STORAGE-1. Native:
 * reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code crypto-scan} (which flags weak ciphers, ECB, static IVs, hardcoded keys
 * and insecure RNG). This scanner asks a different question: when an app <em>does</em> use the
 * AndroidKeyStore, is the key actually <em>protected</em>? A key generated with
 * {@code KeyGenParameterSpec} but <b>without</b> {@code setUserAuthenticationRequired(true)} is
 * usable by anyone who has the unlocked device or who roots it — the hardware backing buys nothing
 * if any process can invoke the key. The scanner works per class so it can see whether a generator
 * spec sets the auth flag anywhere in the same class.
 * <ul>
 *   <li><b>key_no_user_auth</b> (high) — a {@code KeyGenParameterSpec}/{@code KeyPairGenerator}
 *       init in a class that never calls {@code setUserAuthenticationRequired(true)} — the key is
 *       not gated on device unlock / biometric.</li>
 *   <li><b>key_outside_secure_hardware</b> (medium) — never requests StrongBox
 *       ({@code setIsStrongBoxBacked(true)}) — key may live in software-emulated keystore on
 *       devices without a TEE/SE.</li>
 *   <li><b>auth_validity_duration</b> (medium) — {@code setUserAuthenticationValidityDurationSeconds}
 *       with a positive timeout — time-bound auth widens the window for use after a single unlock.</li>
 *   <li><b>key_randomized_encryption_off</b> (high) — {@code setRandomizedEncryptionRequired(false)}
 *       — disables the IV-uniqueness guarantee, enabling deterministic-encryption leaks.</li>
 *   <li><b>legacy_keystore_provider</b> (low) — uses the legacy {@code KeyStore.getInstance("BKS"/
 *       "PKCS12")} / {@code KeyChain} path instead of {@code "AndroidKeyStore"}.</li>
 *   <li><b>keystore_no_password</b> (medium) — {@code KeyStore.load(null} or {@code store(...,null)}
 *       / empty {@code char[0]} protection password on a file-backed keystore.</li>
 *   <li><b>key_user_auth_ok</b> (info) — {@code setUserAuthenticationRequired(true)} present (good).</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * usesAndroidKeyStore, requiresUserAuth, truncated}}.
 */
@Command(name = "keystore-scan",
		description = "Scan Android Keystore key-protection posture (MASVS MSTG-CRYPTO/STORAGE): keys generated without setUserAuthenticationRequired, no StrongBox, randomized-encryption disabled, legacy keystore providers — distinct from crypto-scan (cipher misuse)")
public class KeystoreScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Class-level gate: only classes that touch key generation / the keystore. */
	private static final Pattern KEYSTORE_MARKER = Pattern.compile(
			"KeyGenParameterSpec|AndroidKeyStore|KeyStore\\.getInstance|KeyPairGenerator|KeyGenerator|KeyChain|KeyProtection");

	// Whole-class signals
	private static final Pattern KEYGEN_SPEC = Pattern.compile(
			"KeyGenParameterSpec|KeyProtection\\.Builder|setKeySize\\s*\\(");
	private static final Pattern USER_AUTH_REQUIRED_TRUE = Pattern.compile(
			"setUserAuthenticationRequired\\s*\\(\\s*true");
	private static final Pattern STRONGBOX = Pattern.compile("setIsStrongBoxBacked");
	private static final Pattern ANDROID_KEYSTORE = Pattern.compile("\"AndroidKeyStore\"|AndroidKeyStore");

	// Per-line signals
	private static final Pattern USER_AUTH_LINE = Pattern.compile("setUserAuthenticationRequired\\s*\\(");
	private static final Pattern AUTH_VALIDITY = Pattern.compile(
			"setUserAuthenticationValidityDurationSeconds\\s*\\(");
	private static final Pattern RANDOMIZED_OFF = Pattern.compile(
			"setRandomizedEncryptionRequired\\s*\\(\\s*false");
	private static final Pattern LEGACY_PROVIDER = Pattern.compile(
			"KeyStore\\.getInstance\\s*\\(\\s*\"(BKS|PKCS12|JKS|BouncyCastle)\"|KeyChain");
	private static final Pattern KEYSTORE_LOAD_NULL = Pattern.compile(
			"\\.load\\s*\\(\\s*null|\\.store\\s*\\([^)]*,\\s*null|new\\s+char\\s*\\[\\s*0\\s*\\]");

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
		boolean usesAndroidKeyStore = false;
		boolean requiresUserAuth = false;

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
			if (code == null || code.isEmpty() || !KEYSTORE_MARKER.matcher(code).find()) {
				continue;
			}

			// Whole-class view: does this class build a key generator spec, and does it protect it?
			boolean classHasKeyGen = KEYGEN_SPEC.matcher(code).find();
			boolean classRequiresAuth = USER_AUTH_REQUIRED_TRUE.matcher(code).find();
			boolean classUsesStrongBox = STRONGBOX.matcher(code).find();
			if (ANDROID_KEYSTORE.matcher(code).find()) {
				usesAndroidKeyStore = true;
			}
			if (classRequiresAuth) {
				requiresUserAuth = true;
			}

			String[] lines = code.split("\n", -1);
			boolean reportedNoAuth = false;
			boolean reportedNoStrongBox = false;
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;

				// One high finding per class: a keygen spec that never gates on user auth.
				if (classHasKeyGen && !classRequiresAuth && !reportedNoAuth && KEYGEN_SPEC.matcher(line).find()) {
					findings.add(finding(fullName, ln, "key_no_user_auth", "high",
							"Key generated with no setUserAuthenticationRequired(true) in this class — the key is usable by any process on an unlocked/rooted device; hardware backing buys nothing. Gate the key on device unlock or biometric"));
					highSeverityCount++;
					reportedNoAuth = true;
				}

				if (RANDOMIZED_OFF.matcher(line).find()) {
					findings.add(finding(fullName, ln, "key_randomized_encryption_off", "high",
							"setRandomizedEncryptionRequired(false) — disables IV uniqueness, enabling deterministic-encryption leaks (identical plaintext → identical ciphertext)"));
					highSeverityCount++;
					continue;
				}
				if (AUTH_VALIDITY.matcher(line).find()) {
					findings.add(finding(fullName, ln, "auth_validity_duration", "medium",
							"setUserAuthenticationValidityDurationSeconds(...) — time-bound auth lets the key be used repeatedly after one unlock; prefer per-use auth (CryptoObject) for sensitive keys"));
				} else if (LEGACY_PROVIDER.matcher(line).find()) {
					findings.add(finding(fullName, ln, "legacy_keystore_provider", "low",
							"Legacy file-backed keystore (BKS/PKCS12/JKS/KeyChain) instead of \"AndroidKeyStore\" — keys are not hardware-isolated and the store password is in-app"));
				} else if (KEYSTORE_LOAD_NULL.matcher(line).find() && line.contains("eyStore")) {
					findings.add(finding(fullName, ln, "keystore_no_password", "medium",
							"KeyStore load/store with null or empty protection password — a file-backed keystore is then unprotected at rest"));
				}
			}

			// One per class: keygen spec that never requests StrongBox.
			if (classHasKeyGen && !classUsesStrongBox && !reportedNoStrongBox && findings.size() < limit) {
				findings.add(finding(fullName, 0, "key_outside_secure_hardware", "medium",
						"Key generator never calls setIsStrongBoxBacked(true) — on devices without a TEE/SE the key may live in a software-emulated keystore; request StrongBox and handle StrongBoxUnavailableException"));
				reportedNoStrongBox = true;
			}

			if (classRequiresAuth && findings.size() < limit) {
				findings.add(finding(fullName, 0, "key_user_auth_ok", "info",
						"setUserAuthenticationRequired(true) present — key use is gated on device unlock / biometric (good)"));
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("usesAndroidKeyStore", usesAndroidKeyStore);
		data.put("requiresUserAuth", requiresUserAuth);
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
		return "keystore-scan";
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
