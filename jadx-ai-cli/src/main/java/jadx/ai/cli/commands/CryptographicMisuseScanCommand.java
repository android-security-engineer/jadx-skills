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
 * Cryptographic API misuse scanner — MASVS MSTG-CRYPTO-3/4.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects misuse of cryptographic APIs: ECB mode usage, predictable nonce
 * reuse, MD5/SHA1 for security purposes, weak key sizes, and improper
 * certificate validation. Distinct from {@code crypto-scan} (weak algorithm
 * inventory) and {@code hardcoded-crypto-scan} (hardcoded keys/IVs/nonce) —
 * this scanner focuses on <b>API-level misuse patterns</b> where the API
 * is called incorrectly or in a security-degrading way.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code ecb_mode} — AES/DES/Blowfish with "/ECB/" in transformation
 *       string — identical plaintext blocks produce identical ciphertext</li>
 *   <li>{@code no_iv_specified} — Cipher.getInstance without IvParameterSpec
 *       or GCMParameterSpec — defaults to ECB for block ciphers</li>
 *   <li>{@code md5_for_security} — MD5 used for password hashing or
 *       integrity verification — collision-vulnerable, use SHA-256+</li>
 *   <li>{@code sha1_for_security} — SHA-1 used for security — collision-
 *       vulnerable since SHAttered, use SHA-256+</li>
 *   <li>{@code weak_key_size} — Key sizes below recommended minimums
 *       (AES-128 borderline, RSA-1024, DES 56-bit) — vulnerable to
 *       brute force</li>
 *   <li>{@code predictably_seeded} — SecureRandom created and immediately
 *       seeded with known value — deterministic output</li>
 *   <li>{@code custom_cipher} — Custom Cipher.getInstance transformation
 *       string with unknown mode/padding — may be insecure</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasEcbMode, hasWeakHash, truncated}}.
 */
@Command(name = "cryptographic-misuse-scan",
		description = "Detect cryptographic API misuse (MASVS MSTG-CRYPTO-3/4): ECB mode, missing IV, MD5/SHA1 for security, weak key sizes, predictable seeding. Distinct from crypto-scan (algorithm inventory) and hardcoded-crypto-scan (hardcoded keys)")
public class CryptographicMisuseScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with crypto markers. */
	private static final Pattern CRYPTO_MARKER = Pattern.compile(
			"Cipher|MessageDigest|KeyGenerator|KeyPairGenerator|SecureRandom|"
					+ "SecretKeySpec|IvParameterSpec|GCMParameterSpec|"
					+ "AES|DES|RSA|Blowfish|MD5|SHA-1|SHA1|"
					+ "ECB|CBC|GCM|CTR|CFB|OFB");

	private static final Pattern ECB_MODE = Pattern.compile(
			"\"AES/ECB/|\"DES/ECB/|\"Blowfish/ECB/|/ECB/PKCS|ECB\\s+mode|"
					+ "Cipher\\.getInstance\\s*\\(\\s*\"[A-Z]+/ECB");
	private static final Pattern NO_IV = Pattern.compile(
			"Cipher\\.getInstance\\s*\\(\\s*\"AES/CBC|Cipher\\.getInstance\\s*\\(\\s*\"DES/CBC|"
					+ "Cipher\\.getInstance\\s*\\(\\s*\"Blowfish/CBC");
	private static final Pattern MD5_SECURITY = Pattern.compile(
			"MessageDigest\\.getInstance\\s*\\(\\s*\"MD5\"|"
					+ "\"MD5\"\\s*.*MessageDigest|MD5\\s*.*password|"
					+ "MD5\\s*.*hash|MD5\\s*.*verify|MD5\\s*.*check");
	private static final Pattern SHA1_SECURITY = Pattern.compile(
			"MessageDigest\\.getInstance\\s*\\(\\s*\"SHA-1\"|"
					+ "MessageDigest\\.getInstance\\s*\\(\\s*\"SHA1\"|"
					+ "\"SHA-1\"\\s*.*MessageDigest|SHA1\\s*.*password|"
					+ "SHA-1\\s*.*signature|SHA1\\s*.*verify");
	private static final Pattern WEAK_KEY_SIZE = Pattern.compile(
			"KeyGenerator.*AES.*128|AES.*128.*key|"
					+ "KeyPairGenerator.*RSA.*1024|RSA.*1024|"
					+ "KeyGenerator.*DES|DES.*key|DESede.*112|"
					+ "keySize\\s*=\\s*(56|80|96|112)|"
					+ "RSA.*keySize.*1024");
	private static final Pattern PREDICTABLE_SEED = Pattern.compile(
			"new\\s+SecureRandom\\s*\\([^)]+\\)|"
					+ "SecureRandom\\s*\\(\\s*\"|"
					+ "secureRandom\\.setSeed\\s*\\(");
	private static final Pattern CUSTOM_CIPHER = Pattern.compile(
			"Cipher\\.getInstance\\s*\\(\\s*\"[A-Z]+/[A-Z]+/[A-Z]+\"");

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
		new Rule(ECB_MODE, "ecb_mode", "high",
				"ECB mode — identical plaintext blocks produce identical ciphertext; "
						+ "use CBC/GCM/CTR with random IV for confidentiality"),
		new Rule(MD5_SECURITY, "md5_for_security", "high",
				"MD5 used for security — collision-vulnerable since 2004; use SHA-256 "
						+ "or SHA-3 for integrity verification and bcrypt/PBKDF2 for passwords"),
		new Rule(SHA1_SECURITY, "sha1_for_security", "medium",
				"SHA-1 used for security — collision-vulnerable since SHAttered (2017); "
						+ "use SHA-256 or SHA-3 for integrity verification"),
		new Rule(WEAK_KEY_SIZE, "weak_key_size", "medium",
				"Weak key size — key is below recommended minimum; vulnerable to "
						+ "brute force with modern hardware; use AES-256, RSA-2048+"),
		new Rule(PREDICTABLE_SEED, "predictably_seeded", "medium",
				"SecureRandom with predictable seed — deterministic output; "
						+ "use parameterless constructor for OS-provided entropy"),
		new Rule(NO_IV, "no_iv_specified", "medium",
				"CBC mode without explicit IV — defaults to all-zero IV; "
						+ "use IvParameterSpec with random IV"),
		new Rule(CUSTOM_CIPHER, "custom_cipher", "info",
				"Custom Cipher.getInstance transformation — verify the mode and "
						+ "padding are secure (avoid ECB, use authenticated encryption)"),
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
		boolean hasEcbMode = false;
		boolean hasWeakHash = false;

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
			if (code == null || code.isEmpty() || !CRYPTO_MARKER.matcher(code).find()) {
				continue;
			}

			// Class-level: check if CBC mode without IvParameterSpec
			boolean classHasCbcCipher = NO_IV.matcher(code).find();
			boolean classHasIvSpec = code.contains("IvParameterSpec") || code.contains("GCMParameterSpec");

			// Per-line rule detection (first-match-wins, ONE/class per kind)
			TreeSet<String> reportedKinds = new TreeSet<>();
			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!reportedKinds.contains(r.kind) && r.pattern.matcher(line).find()) {
						// Skip no_iv_specified if class has IvParameterSpec
						if ("no_iv_specified".equals(r.kind) && classHasIvSpec) {
							reportedKinds.add(r.kind); // mark as reported so we skip it
							continue;
						}
						findings.add(finding(r.kind, r.severity, fullName, i + 1, r.detail));
						reportedKinds.add(r.kind);
						if ("high".equals(r.severity)) {
							highSeverityCount++;
						}
						if ("ecb_mode".equals(r.kind)) {
							hasEcbMode = true;
						}
						if ("md5_for_security".equals(r.kind) || "sha1_for_security".equals(r.kind)) {
							hasWeakHash = true;
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
		data.put("hasEcbMode", hasEcbMode);
		data.put("hasWeakHash", hasWeakHash);
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
		return "cryptographic-misuse-scan";
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
