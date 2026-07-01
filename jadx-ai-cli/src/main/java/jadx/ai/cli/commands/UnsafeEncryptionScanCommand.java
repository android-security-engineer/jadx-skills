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
 * Unsafe-encryption scanner — MASVS MSTG-CRYPTO.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Detects custom/unsafe encryption implementations: homemade cipher
 * algorithms, insecure TLS versions, RC4/DES usage, custom padding
 * schemes, and XOR-based "encryption". Distinct from
 * {@code crypto-scan} (algorithm inventory), {@code hardcoded-crypto-scan}
 * (hardcoded keys/IVs), and {@code cryptographic-misuse-scan} (API-level
 * misuse like ECB mode) — this scanner focuses on <b>fundamentally broken
 * or custom encryption approaches</b>.
 *
 * <p>Categories (first-match-wins per line, ONE/class per kind):
 * <ul>
 *   <li>{@code custom_encryption} — Custom encrypt/decrypt methods that don't
 *       use standard Cipher API — likely insecure, use platform crypto</li>
 *   <li>{@code xor_encryption} — XOR-based "encryption" — trivially reversible;
 *       not real encryption</li>
 *   <li>{@code rc4_usage} — RC4 stream cipher — vulnerable to multiple attacks
 *       (Fluhrer/Mantin/Shamir, bias attacks); deprecated</li>
 *   <li>{@code des_usage} — DES/3DES/DESede — 56-bit key brute-forceable;
 *       use AES-256</li>
 *   <li>{@code insecure_tls_version} — SSLv3/TLS1.0/TLS1.1 enabled —
 *       vulnerable to POODLE/BEAST and other protocol attacks</li>
 *   <li>{@code custom_padding} — Custom padding implementation instead of
 *       PKCS5/PKCS7/OAEP — may be vulnerable to padding oracle attacks</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasCustomCrypto, hasWeakCipher, truncated}}.
 */
@Command(name = "unsafe-encryption-scan",
		description = "Detect custom/unsafe encryption (MASVS MSTG-CRYPTO): homemade ciphers, XOR encryption, RC4/DES, insecure TLS (SSLv3/TLS1.0), custom padding. Distinct from crypto-scan/hardcoded-crypto-scan/cryptographic-misuse-scan")
public class UnsafeEncryptionScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes with encryption markers. */
	private static final Pattern ENCRYPT_MARKER = Pattern.compile(
			"encrypt|decrypt|cipher|Cipher|crypto|Crypto|XOR|xor|"
					+ "RC4|DES|DESede|SSL|TLS|padding|Padding|"
					+ "0x[0-9a-fA-F]|\\^\\s*0x|\\^\\s*key");

	private static final Pattern CUSTOM_ENCRYPTION = Pattern.compile(
			"private.*encrypt\\s*\\(|public.*encrypt\\s*\\(|"
					+ "private.*decrypt\\s*\\(|public.*decrypt\\s*\\(|"
					+ "customEncrypt|customDecrypt|myEncrypt|simpleEncrypt|"
					+ "doEncrypt\\s*\\(|doDecrypt\\s*\\(");
	private static final Pattern XOR_ENCRYPTION = Pattern.compile(
			"\\^\\s*0x[0-9a-fA-F]|\\^\\s*key\\b|\\^\\s*secretKey|"
					+ "XOR.*encrypt|xorEncrypt|XORCipher|"
					+ "simpleXor|\\^\\s*\\(\\s*byte|byte.*\\^.*byte");
	private static final Pattern RC4_USAGE = Pattern.compile(
			"RC4|ARCFOUR|Arcfour|rc4|RC4Cipher|"
					+ "\"RC4\"|ARC4");
	private static final Pattern DES_USAGE = Pattern.compile(
			"\"DES\"|\"DESede\"|DES/CBC|DES/ECB|DES/OFB|DES/CFB|"
					+ "DESede/CBC|DESede/ECB|KeyGenerator.*DES|"
					+ "DESEDE|DESede|Blowfish");
	private static final Pattern INSECURE_TLS = Pattern.compile(
			"SSLv3|TLSv1\\b|TLSv1\\.1|SSLContext.*SSL|"
					+ "\"SSL\"|\"TLSv1\"|\"TLSv1\\.1\"|"
					+ "setEnabledProtocols.*SSL|SSLv3|"
					+ "setProtocol.*SSL|PROTOCOL_SSL|PROTOCOL_TLSV1\\b");
	private static final Pattern CUSTOM_PADDING = Pattern.compile(
			"customPadding|CustomPadding|myPadding|PKCS1Padding|"
					+ "NoPadding|ISO10126Padding|X923Padding|"
					+ "implementPadding|paddingScheme\\s*=");

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
		new Rule(XOR_ENCRYPTION, "xor_encryption", "high",
				"XOR-based 'encryption' — trivially reversible by XOR with same key; "
						+ "not real encryption; use AES-GCM or ChaCha20-Poly1305"),
		new Rule(CUSTOM_ENCRYPTION, "custom_encryption", "high",
				"Custom encrypt/decrypt method — likely insecure; use platform "
						+ "javax.crypto.Cipher with standard algorithms (AES-GCM)"),
		new Rule(RC4_USAGE, "rc4_usage", "high",
				"RC4 stream cipher — vulnerable to Fluhrer/Mantin/Shamir attack "
						+ "and statistical bias; use AES-GCM or ChaCha20-Poly1305"),
		new Rule(DES_USAGE, "des_usage", "high",
				"DES/3DES/Blowfish cipher — DES has 56-bit key (brute-forceable); "
						+ "3DES is deprecated; use AES-256"),
		new Rule(INSECURE_TLS, "insecure_tls_version", "high",
				"Insecure TLS version enabled (SSLv3/TLS1.0/TLS1.1) — vulnerable to "
						+ "POODLE/BEAST and other protocol attacks; enforce TLS 1.2+"),
		new Rule(CUSTOM_PADDING, "custom_padding", "medium",
				"Custom or unusual padding scheme — may be vulnerable to padding oracle "
						+ "attacks; use PKCS7Padding with authenticated encryption (GCM)"),
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
		boolean hasCustomCrypto = false;
		boolean hasWeakCipher = false;

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
			if (code == null || code.isEmpty() || !ENCRYPT_MARKER.matcher(code).find()) {
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
						if ("custom_encryption".equals(r.kind) || "xor_encryption".equals(r.kind)) {
							hasCustomCrypto = true;
						}
						if ("rc4_usage".equals(r.kind) || "des_usage".equals(r.kind)) {
							hasWeakCipher = true;
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
		data.put("hasCustomCrypto", hasCustomCrypto);
		data.put("hasWeakCipher", hasWeakCipher);
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
		return "unsafe-encryption-scan";
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
