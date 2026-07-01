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
 * Insecure Android KeyStore usage scanner — MASVS MSTG-CRYPTO-5.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code keystore-scan} (inventories KeyStore API usage — what keystore
 * type, what entries) and {@code crypto-scan} (generic cryptographic issues — weak algorithms,
 * hardcoded keys). This scanner focuses on <b>Android KeyStore security misconfigurations</b>:
 * keys that can be extracted, keys not bound to device credentials, and insecure key properties.
 *
 * <p>Categories (first-match-wins per line):
 * <ul>
 *   <li>{@code key_extractable} — KeyGenParameterSpec with {@code setUserAuthenticationRequired=false}
 *       and no other protection, or explicitly set {@code setUnlockedDeviceRequired=false} — key
 *       material can be used without user authentication</li>
 *   <li>{@code key_no_auth} — KeyGenParameterSpec with
 *       {@code setUserAuthenticationRequired(false)} — the key does not require the user
 *       to authenticate; any app with keystore access can use it</li>
 *   <li>{@code insecure_key_algorithm} — KeyPairGenerator / KeyGenerator with insecure
 *       algorithm ({@code RSA/ECB/PKCS1Padding}, {@code AES/ECB}, {@code DES}, {@code MD5},
 *       {@code SHA1} for signing) in a KeyStore context</li>
 *   <li>{@code key_not_bound_to_device} — Key imported into KeyStore without
 *       {@code KeyProtection.Builder} / {@code setBoundToSpecificSecureHardware} — key can be
 *       extracted from the KeyStore</li>
 *   <li>{@code keystore_credential} — {@code KeyStore.getInstance} with password parameter
 *       ({@code keystore.load(stream, password)}) — KeyStore credential may be hardcoded</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, truncated}}.
 */
@Command(name = "insecure-keystore-scan",
		description = "Detect insecure Android KeyStore usage (MASVS MSTG-CRYPTO-5): keys without user auth requirement, extractable keys, insecure algorithms in KeyStore context, keys not bound to secure hardware, KeyStore with hardcoded credentials. Distinct from keystore-scan (API inventory) and crypto-scan (generic weak crypto)")
public class InsecureKeystoreScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes that use Android KeyStore. */
	private static final Pattern KEYSTORE_MARKER = Pattern.compile(
			"KeyStore|KeyGenParameterSpec|KeyPairGenerator|KeyGenerator|KeyProtection");

	private static final Pattern SET_USER_AUTH_REQUIRED_FALSE = Pattern.compile(
			"setUserAuthenticationRequired\\s*\\(\\s*false");
	private static final Pattern SET_USER_AUTH_REQUIRED_TRUE = Pattern.compile(
			"setUserAuthenticationRequired\\s*\\(\\s*true");
	/** Explicitly disables the unlocked-device requirement — key material usable on a locked device. */
	static final Pattern SET_UNLOCKED_DEVICE_FALSE = Pattern.compile(
			"setUnlockedDeviceRequired\\s*\\(\\s*false");

	/**
	 * Key-import sink — a key materialised into the KeyStore via {@code setEntry}. Matched at
	 * <b>class scope</b> for {@code key_not_bound_to_device}: the import and the (missing) protection
	 * are independent statements, so a same-line AND would never fire. Package-private for testing.
	 */
	static final Pattern KEY_IMPORT = Pattern.compile(
			"\\.setEntry\\s*\\(|KeyStore\\.setEntry");

	/**
	 * The protection that binds an imported key to secure hardware — its <b>absence</b> is the
	 * {@code key_not_bound_to_device} signal. Package-private for testing.
	 */
	static final Pattern KEY_PROTECTION_GUARD = Pattern.compile(
			"KeyProtection\\.Builder|setBoundToSpecificSecureHardware|importKey\\s*\\([^)]*KeyProtection");
	private static final Pattern INSECURE_ALGO = Pattern.compile(
			"AES/ECB|RSA/ECB/PKCS1Padding|DES|DESede|Blowfish|RC4|"
					+ "KeyPairGenerator\\.getInstance\\s*\\(\\s*\"DSA\"|"
					+ "KeyGenerator\\.getInstance\\s*\\(\\s*\"DES\"|"
					+ "Signature\\.getInstance\\s*\\(\\s*\"SHA1|"
					+ "MessageDigest\\.getInstance\\s*\\(\\s*\"MD5|"
					+ "MessageDigest\\.getInstance\\s*\\(\\s*\"SHA1|"
					+ "Cipher\\.getInstance\\s*\\(\\s*\"AES/ECB");
	private static final Pattern KEYSTORE_PASSWORD = Pattern.compile(
			"KeyStore\\.getInstance|keystore\\.load\\s*\\(");
	private static final Pattern HARDCODED_PASSWORD = Pattern.compile(
			"load\\s*\\([^,]+,\\s*\"[^\"]+\"|load\\s*\\([^,]+,\\s*\\w+\\s*\\.toCharArray");

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
			if (code == null || code.isEmpty() || !KEYSTORE_MARKER.matcher(code).find()) {
				continue;
			}

			boolean reportedNoAuth = false;
			boolean reportedInsecureAlgo = false;
			boolean reportedHardcodedPassword = false;
			boolean reportedExtractable = false;

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				// Key without user auth requirement
				if (!reportedNoAuth && SET_USER_AUTH_REQUIRED_FALSE.matcher(line).find()) {
					findings.add(finding("key_no_auth", "high", fullName, i + 1,
							"setUserAuthenticationRequired(false) — key can be used without user "
									+ "authentication (biometric/PIN); any app with keystore access can use this key"));
					highSeverityCount++;
					reportedNoAuth = true;
					continue;
				}

				// Key explicitly usable on a locked device — extractable-without-unlock signal
				if (!reportedExtractable && SET_UNLOCKED_DEVICE_FALSE.matcher(line).find()) {
					findings.add(finding("key_extractable", "medium", fullName, i + 1,
							"setUnlockedDeviceRequired(false) — key material can be used while the device "
									+ "is locked; combine with setUserAuthenticationRequired(true) so the key "
									+ "is only available after biometric/PIN unlock"));
					reportedExtractable = true;
					continue;
				}

				// Insecure algorithm in KeyStore context
				if (!reportedInsecureAlgo && INSECURE_ALGO.matcher(line).find()) {
					findings.add(finding("insecure_key_algorithm", "high", fullName, i + 1,
							"Insecure algorithm used in KeyStore context — ECB mode, PKCS1 padding, "
									+ "DES, or weak hash; use GCM/CBC for AES, OAEP for RSA, SHA-256+ for hashing"));
					highSeverityCount++;
					reportedInsecureAlgo = true;
					continue;
				}

				// KeyStore with hardcoded password
				if (!reportedHardcodedPassword && HARDCODED_PASSWORD.matcher(line).find()) {
					findings.add(finding("keystore_credential", "medium", fullName, i + 1,
							"KeyStore.load() with apparent hardcoded password — the keystore credential "
									+ "can be extracted from the APK; use user-provided credentials or "
									+ "Android Keystore which does not require a password"));
					reportedHardcodedPassword = true;
				}
			}

			// Class-level: KeyGenParameterSpec used but setUserAuthenticationRequired never called
			if (!reportedNoAuth && code.contains("KeyGenParameterSpec")
					&& !SET_USER_AUTH_REQUIRED_TRUE.matcher(code).find()
					&& !SET_USER_AUTH_REQUIRED_FALSE.matcher(code).find()) {
				findings.add(finding("key_no_auth", "high", fullName, 0,
						"KeyGenParameterSpec used but setUserAuthenticationRequired() never called — "
								+ "key defaults to not requiring user auth; add setUserAuthenticationRequired(true)"));
				highSeverityCount++;
			}

			// Class-level: a key imported into the KeyStore (setEntry) without KeyProtection.Builder —
			// the imported key is not bound to secure hardware and can be extracted. The import and the
			// (missing) protection are independent statements, so this is a class-scope AND, not per-line.
			if (findings.size() < limit
					&& KEY_IMPORT.matcher(code).find()
					&& !KEY_PROTECTION_GUARD.matcher(code).find()) {
				findings.add(finding("key_not_bound_to_device", "medium", fullName, 0,
						"Key imported into KeyStore via setEntry without KeyProtection.Builder — the key "
								+ "is not bound to secure hardware and can be extracted; wrap imports in "
								+ "KeyProtection.Builder().setBoundToSpecificSecureHardware(true)"));
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
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
		return "insecure-keystore-scan";
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
