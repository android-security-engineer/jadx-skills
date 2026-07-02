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
 * Hardcoded-crypto-parameter scanner — MASVS MSTG-CRYPTO-2.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects hardcoded cryptographic parameters: fixed IVs, static salts,
 * embedded symmetric keys, hardcoded padding parameters. Distinct from
 * {@code crypto-scan} (weak algorithms/modes) and {@code secrets-scan}
 * (generic credential/API-key leakage) — this scanner focuses on
 * <b>crypto-operation parameters that should be dynamic but are hardcoded</b>.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code hardcoded_iv} — Fixed initialization vector in cipher operations
 *       (IvParameterSpec with literal byte array, "0123456789abcdef" as IV string, or the
 *       variable-indirect {@code byte[] iv = "...".getBytes()} source line jadx emits before
 *       {@code new IvParameterSpec(iv)})
 *       — identical ciphertext for same plaintext, enables pattern analysis</li>
 *   <li>{@code hardcoded_salt} — Static salt in PBE/KeyDerivation
 *       (PBEParameterSpec with fixed salt, hardcoded salt byte array in PBKDF2)
 *       — weakens key derivation against rainbow-table attacks</li>
 *   <li>{@code hardcoded_symmetric_key} — Symmetric key as string literal or byte
 *       array in code (AES key = "1234567890abcdef", SecretKeySpec with literal, or the
 *       variable-indirect name-gated {@code byte[] keyBytes = "...".getBytes()} source line)
 *       — key extractable from APK, no real security</li>
 *   <li>{@code hardcoded_key_bytes} — Key material as hex/base64 literal
 *       (byte[]{0x12,0x34,...}, byte[]{(byte)0x12,...} jadx cast form, byte[]{65,66,...}
 *       pure-decimal jadx form for values &lt;128, "AQIDBA==" base64 key)
 *       — key extractable from decompiled code</li>
 *   <li>{@code hardcoded_nonce} — Fixed nonce/counter in AES-GCM/CTR
 *       (GCMParameterSpec with fixed nonce, replayed counter)
 *       — breaks authenticated encryption uniqueness requirement</li>
 *   <li>{@code hardcoded_seed} — Fixed seed for SecureRandom
 *       (SecureRandom(seed), setSeed with constant)
 *       — deterministic RNG, predictable output</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasHardcodedIv, hasHardcodedKey, truncated}}.
 */
@Command(name = "hardcoded-crypto-scan",
		description = "Detect hardcoded crypto parameters (MASVS MSTG-CRYPTO-2): fixed IV, static salt, embedded symmetric keys, hardcoded nonce, fixed SecureRandom seed. Distinct from crypto-scan (algorithm weakness) and secrets-scan (generic credential leakage)")
public class HardcodedCryptoScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with crypto markers. */
	/**
	 * Gate: only scan classes that touch crypto. Kept in sync with the field-name arms of
	 * {@link #HARDCODED_KEY_BYTES} ({@code KEY_BYTES}/{@code keyBytes}) and {@link #HARDCODED_SALT}
	 * ({@code SALT}/{@code salt}): a constant-holder class
	 * ({@code static final byte[] KEY_BYTES = "...".getBytes()}) with no other crypto token was skipped
	 * at the gate, so {@code hardcoded_key_bytes}/{@code hardcoded_salt} never fired. Gate looseness is
	 * safe — it only decides whether to scan; findings come from the rule Patterns. Deliberately does NOT
	 * add bare {@code KEY}/{@code IV}/{@code nonce} (too broad — matches keyEvent/roman-numeral/variable
	 * names); only the specific field-name tokens the rules look for.
	 * Package-private for testing.
	 */
	static final Pattern CRYPTO_MARKER = Pattern.compile(
			"IvParameterSpec|GCMParameterSpec|PBEParameterSpec|SecretKeySpec|"
					+ "SecureRandom|PBKDF2|setSeed|KeySpec|Cipher|"
					+ "AES|DES|RSA|Blowfish|ChaCha20|0x[0-9a-fA-F]{2}|"
					+ "KEY_BYTES|keyBytes|\\bSALT\\b|\\bsalt\\b|\\bSEED\\b|\\bseed\\b");

	/**
	 * Hardcoded IV. Covers the inline form ({@code new IvParameterSpec(new byte[]{...})}) AND the
	 * variable-indirect source line jadx emits when the IV is extracted first:
	 * {@code byte[] iv = "0102030405060708".getBytes(); ... new IvParameterSpec(iv);}. The sink line
	 * {@code new IvParameterSpec(iv)} has no literal, so the inline arm misses it — the source-line arm
	 * ({@code byte[]\s*\w*\s*=\s*"[^"]{8,}"\.getBytes}) closes that gap. The {@code {8,}} floor avoids
	 * short-string FP. Package-private for testing.
	 */
	static final Pattern HARDCODED_IV = Pattern.compile(
			// The inline `IvParameterSpec("...")` arm allows an optional `(` after `\s*`: when an IV is
			// assembled via StringBuilder.append("part1").append("part2") (a common obfuscation idiom),
			// javac/d8 constant-folds the chain and jadx emits `IvParameterSpec(("0102030405060708").getBytes())`
			// — an EXTRA paren around the folded literal. Without `\(?` the inline arm missed this form
			// (a high-severity FN on the most common key/IV obfuscation trick). Verified via javac→d8→jadx.
			"IvParameterSpec\\s*\\(\\s*\\(?\\s*(new\\s+byte\\[|\"[^\"]{8,}\")|"
					+ "IV\\s*=\\s*\"[^\"]{8,}\"|"
					+ "initVector\\s*=\\s*\"[^\"]{8,}\"|"
					+ "ivSpec\\s*=\\s*new\\s+IvParameterSpec|"
					+ "\"[0-9a-fA-F]{16,32}\"\\s*.*IvParameter|"
					// Name-gated source-line arm (mirrors HARDCODED_SYMMETRIC_KEY): the bare
					// `byte[] \w* = "...".getBytes` arm was a FALSE-POSITIVE AMPLIFIER — a non-IV
					// buffer in a crypto class (a digest magic "SIGMAGIC9", a signature prefix, a
					// file header) jadx keeps as `byte[] bytes = "...".getBytes()` was flagged
					// hardcoded_iv high. Now requires an IV-ish variable name
					// (iv|Iv|IV|nonce|initVector|initializationVector); the inline
					// `IvParameterSpec("...")` arm still catches the un-named case.
					+ "byte\\[\\]\\s*(?:\\w*(?:iv|Iv|IV|nonce|initVector|initializationVector)\\w*|IV[A-Z_]*)\\s*=\\s*\"[^\"]{8,}\"\\.getBytes");
	private static final Pattern HARDCODED_SALT = Pattern.compile(
			"PBEParameterSpec\\s*\\(\\s*(new\\s+byte\\[|\"[^\"]+\")|"
					+ "salt\\s*=\\s*\"[^\"]{4,}\"|"
					+ "SALT\\s*=\\s*(new\\s+byte|\"[^\"]{4,}\")|"
					+ "PBKDF2WithHmac.*salt|hardcodedSalt|fixedSalt");
	/**
	 * Hardcoded symmetric key. Covers the inline form ({@code new SecretKeySpec("...".getBytes(), "AES")})
	 * AND the variable-indirect source line jadx emits when the key is extracted first:
	 * {@code byte[] keyBytes = "MySecretKey123".getBytes(); ... new SecretKeySpec(keyBytes, "AES");}. The
	 * sink line {@code new SecretKeySpec(keyBytes, ...)} has no literal, so the inline arm misses it — the
	 * source-line arm closes that gap. The source-line arm is name-gated
	 * ({@code \w*(?:key|Key|aes|Aes|secret|Secret)\w*|KEY[A-Z_]*}) so a generic
	 * {@code byte[] data = "...".getBytes()} (non-key buffer) does not fire. Package-private for testing.
	 */
	static final Pattern HARDCODED_SYMMETRIC_KEY = Pattern.compile(
			// The inline `SecretKeySpec("...")` arm allows an optional `(` after `\s*`: when a key is
			// assembled via StringBuilder.append("part1").append("part2") (a common obfuscation idiom),
			// javac/d8 constant-folds the chain and jadx emits `SecretKeySpec(("MySuperSecretKey123456").getBytes(), "AES")`
			// — an EXTRA paren around the folded literal. Without `\(?` this high-severity rule missed the
			// most common key-obfuscation trick. Verified via javac→d8→jadx.
			"SecretKeySpec\\s*\\(\\s*\\(?\\s*(\"[^\"]+\"|new\\s+byte)|"
					+ "AES_KEY\\s*=\\s*\"[^\"]+\"|"
					+ "SECRET_KEY\\s*=\\s*\"[^\"]+\"|"
					+ "ENCRYPTION_KEY\\s*=\\s*\"[^\"]+\"|"
					+ "aesKey\\s*=\\s*\"[^\"]+\"|"
					+ "byte\\[\\]\\s*(?:\\w*(?:key|Key|aes|Aes|secret|Secret)\\w*|KEY[A-Z_]*)\\s*=\\s*\"[^\"]{8,}\"\\.getBytes|"
						// Field-indirect form: a `static final String KEY = "..."` field whose value flows to
						// SecretKeySpec on another line (the sink line has no literal). jadx does NOT inline a
						// `static final String` field into its use sites (unlike `static final int`), so the
						// declaration survives and is the only place the literal appears. The field name must be
						// an EXACT key-ish token (not a substring) to avoid flagging `KEYWORDS`/`keyDesc` — the
						// recurring .*-substring FP pattern. The CRYPTO_MARKER class gate (SecretKeySpec/Cipher)
						// further scopes this to crypto classes. Verified via javac→d8→jadx.
						+ "(?:static\\s+)?(?:final\\s+)?String\\s+(?:KEY|SECRET_KEY|AES_KEY|ENCRYPTION_KEY|API_KEY|PRIVATE_KEY|aesKey|secretKey|encryptionKey|apiKey|privateKey)\\b\\s*=\\s*\"[^\"]{8,}\"");
	/**
	 * Hardcoded key material as a byte-array literal or base64 string. Covers the {@code new byte[]{0x..}}
	 * hex-literal form, the jadx-specific {@code new byte[]{(byte)0x12, (byte)0x34}} cast form (jadx casts
	 * byte literals because signed-byte overflow), AND the {@code new byte[]{65, 66, 67}} pure-decimal form
	 * — jadx emits byte values &lt;128 as bare decimals (no {@code 0x} prefix, no {@code (byte)} cast), so
	 * the hex/cast arms alone missed the most common dex2c/packed-layout key-array shape. The decimal arm
	 * requires the digit to be followed by {@code ,} or {@code }} so a method signature
	 * {@code void f(byte[] p)} or a sized {@code new byte[16]} (no {@code \{} body) does not fire.
	 * Package-private for testing.
	 */
	static final Pattern HARDCODED_KEY_BYTES = Pattern.compile(
			"byte\\[\\]\\s*\\{\\s*(?:0x[0-9a-fA-F]|\\(byte\\)\\s*0x[0-9a-fA-F]|\\d{1,3}\\s*[,}])|"
					+ "\"[A-Za-z0-9+/]{20,}={0,2}\"\\s*.*SecretKeySpec|"
					+ "keyBytes\\s*=\\s*\"[^\"]+\"|"
					+ "KEY_BYTES\\s*=\\s*(new\\s+byte|\"[^\"]+\")");
	/**
	 * Hardcoded GCM nonce. The inline {@code GCMParameterSpec(bits, "...")} arm allows an optional
	 * {@code (} after the comma: when the nonce is assembled via StringBuilder.append(...).append(...)
	 * (a common obfuscation idiom), javac/d8 constant-folds the chain and jadx emits
	 * {@code GCMParameterSpec(128, ("01020304050607").getBytes())} — an EXTRA paren around the folded
	 * literal. Without {@code \(?} this high-severity rule missed the obfuscated form. Verified via
	 * javac&#8594;d8&#8594;jadx. Package-private for testing.
	 */
	static final Pattern HARDCODED_NONCE = Pattern.compile(
			"GCMParameterSpec\\s*\\(\\s*[0-9]+\\s*,\\s*\\(?\\s*(new\\s+byte\\[|\"[^\"]+\")|"
					+ "nonce\\s*=\\s*\"[^\"]{6,}\"|"
					+ "GCM_NONCE\\s*=\\s*\"[^\"]+\"|"
					+ "fixedNonce|constantNonce");
	/**
	 * Hardcoded SecureRandom seed. Covers {@code setSeed("...")}/{@code setSeed(new byte[...])}/
	 * {@code setSeed(123L)} AND the no-suffix {@code setSeed(123)} form — jadx frequently emits the
	 * long literal without the {@code L} suffix, so the {@code [0-9]+L} arm alone missed it. The bare
	 * numeric arm requires the digit to be followed by {@code ;} or {@code )} so a variable-backed
	 * {@code setSeed(seed.length)} does not fire. Package-private for testing.
	 */
	static final Pattern HARDCODED_SEED = Pattern.compile(
			"SecureRandom\\s*\\(\\s*\"[^\"]+\"|"
					+ "setSeed\\s*\\(\\s*(new\\s+byte\\[|\"[^\"]+\"|[0-9]+L|[0-9]+\\s*[;)])|"
					+ "SEED\\s*=\\s*(new\\s+byte|\"[^\"]+\"|[0-9]+L)");

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
		new Rule(HARDCODED_IV, "hardcoded_iv", "high",
				"Hardcoded IV — identical ciphertext for same plaintext, enables pattern "
						+ "analysis and known-plaintext attacks; IV must be random/unique per encryption"),
		new Rule(HARDCODED_NONCE, "hardcoded_nonce", "high",
				"Hardcoded nonce/counter in AEAD — breaks uniqueness requirement of "
						+ "AES-GCM/CTR; nonce reuse reveals XOR of plaintexts and forges tags"),
		new Rule(HARDCODED_SYMMETRIC_KEY, "hardcoded_symmetric_key", "high",
				"Hardcoded symmetric key — extractable from APK/package; no real secrecy; "
						+ "use Android Keystore for key storage"),
		new Rule(HARDCODED_KEY_BYTES, "hardcoded_key_bytes", "high",
				"Hardcoded key material as byte array or base64 — extractable from "
						+ "decompiled code; use Android Keystore or secure key derivation"),
		new Rule(HARDCODED_SALT, "hardcoded_salt", "medium",
				"Hardcoded salt in key derivation — weakens PBKDF2/PBE against "
						+ "rainbow-table attacks; salt should be random per derivation"),
		new Rule(HARDCODED_SEED, "hardcoded_seed", "medium",
				"Hardcoded SecureRandom seed — produces deterministic random output; "
						+ "anyone decompiling the APK can reproduce the sequence"),
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
		boolean hasHardcodedIv = false;
		boolean hasHardcodedKey = false;

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
						if ("hardcoded_iv".equals(r.kind) || "hardcoded_nonce".equals(r.kind)) {
							hasHardcodedIv = true;
						}
						if ("hardcoded_symmetric_key".equals(r.kind) || "hardcoded_key_bytes".equals(r.kind)) {
							hasHardcodedKey = true;
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
		data.put("hasHardcodedIv", hasHardcodedIv);
		data.put("hasHardcodedKey", hasHardcodedKey);
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
		return "hardcoded-crypto-scan";
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
