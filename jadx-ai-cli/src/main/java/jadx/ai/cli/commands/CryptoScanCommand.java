package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Scans decompiled code for cryptographic API usage and flags common misuse — the static half of
 * the {@code crypto-analysis} workflow, absorbed into one pass instead of a dozen manual searches.
 * Native capability: reads jadx's parsed model, no external tool. Detects:
 * <ul>
 *   <li>weak ciphers (DES/3DES/RC4/RC2/Blowfish) and ECB mode (incl. the implicit-ECB default of a
 *       bare {@code "AES"} transformation)</li>
 *   <li>weak hashes (MD5, SHA-1) and weak MACs</li>
 *   <li>hardcoded keys / static IVs ({@code SecretKeySpec}/{@code IvParameterSpec} over literals)</li>
 *   <li>insecure RNG ({@code new Random()} / {@code Math.random()}) in crypto-bearing classes</li>
 * </ul>
 */
@Command(name = "crypto-scan", description = "Scan code for cryptographic API usage and flag misuse (weak ciphers, ECB, weak hashes, hardcoded keys)")
public class CryptoScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Algorithms considered broken for confidentiality. */
	private static final Set<String> WEAK_CIPHERS = Set.of("DES", "DESEDE", "RC4", "ARCFOUR", "RC2", "BLOWFISH");
	/** Hashes too weak for security use (collision / preimage concerns). */
	private static final Set<String> WEAK_HASHES = Set.of("MD2", "MD4", "MD5", "SHA-1", "SHA1", "SHA");

	private static final Pattern CIPHER_GET = Pattern.compile("Cipher\\.getInstance\\(\\s*\"([^\"]+)\"");
	private static final Pattern DIGEST_GET = Pattern.compile("MessageDigest\\.getInstance\\(\\s*\"([^\"]+)\"");
	private static final Pattern MAC_GET = Pattern.compile("Mac\\.getInstance\\(\\s*\"([^\"]+)\"");
	private static final Pattern SECRET_KEY = Pattern.compile("new\\s+SecretKeySpec\\(");
	private static final Pattern IV_LITERAL = Pattern.compile("new\\s+IvParameterSpec\\(\\s*new\\s+byte\\[\\]");
	private static final Pattern INSECURE_RANDOM = Pattern.compile("new\\s+Random\\(|Math\\.random\\(");
	// Markers that a class actually does crypto, so insecure-RNG noise is scoped to crypto code.
	private static final Pattern CRYPTO_MARKER =
			Pattern.compile("javax\\.crypto|Cipher|SecretKeySpec|KeyGenerator|MessageDigest|\\bMac\\b|KeyPairGenerator");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();

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
			boolean cryptoClass = CRYPTO_MARKER.matcher(code).find();
			scanText(code, fullName, cryptoClass, findings);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private void scanText(String code, String cls, boolean cryptoClass, List<Map<String, Object>> findings) {
		String[] lines = code.split("\n", -1);
		for (int i = 0; i < lines.length && findings.size() < limit; i++) {
			String line = lines[i];
			int ln = i + 1;

			Matcher cm = CIPHER_GET.matcher(line);
			while (cm.find() && findings.size() < limit) {
				classifyCipher(cm.group(1), cls, ln, findings);
			}
			Matcher dm = DIGEST_GET.matcher(line);
			while (dm.find() && findings.size() < limit) {
				String algo = dm.group(1);
				boolean weak = WEAK_HASHES.contains(algo.toUpperCase(Locale.ROOT));
				findings.add(finding(cls, ln, "hash", weak ? "high" : "info",
						algo, weak ? "Weak hash algorithm: " + algo : "Hash algorithm: " + algo));
			}
			Matcher mm = MAC_GET.matcher(line);
			while (mm.find() && findings.size() < limit) {
				String algo = mm.group(1);
				boolean weak = algo.toUpperCase(Locale.ROOT).contains("MD5") || algo.toUpperCase(Locale.ROOT).contains("SHA1");
				findings.add(finding(cls, ln, "mac", weak ? "medium" : "info",
						algo, "MAC algorithm: " + algo));
			}
			if (SECRET_KEY.matcher(line).find() && findings.size() < limit) {
				findings.add(finding(cls, ln, "key_handling", "medium", "SecretKeySpec",
						"SecretKeySpec construction — verify the key is not hardcoded"));
			}
			if (IV_LITERAL.matcher(line).find() && findings.size() < limit) {
				findings.add(finding(cls, ln, "static_iv", "medium", "IvParameterSpec",
						"IV built from an inline byte[] literal — likely a static/hardcoded IV"));
			}
			if (cryptoClass && INSECURE_RANDOM.matcher(line).find() && findings.size() < limit) {
				findings.add(finding(cls, ln, "insecure_random", "medium", "Random",
						"Non-cryptographic RNG in a crypto class — use SecureRandom"));
			}
		}
	}

	/** Parse an {@code algorithm/mode/padding} transformation and flag weak algorithm or mode. */
	private void classifyCipher(String transformation, String cls, int ln, List<Map<String, Object>> findings) {
		String[] parts = transformation.split("/");
		String algo = parts[0].trim().toUpperCase(Locale.ROOT);
		String mode = parts.length > 1 ? parts[1].trim().toUpperCase(Locale.ROOT) : null;

		if (WEAK_CIPHERS.contains(algo)) {
			findings.add(finding(cls, ln, "weak_cipher", "high", transformation,
					"Broken/weak cipher algorithm: " + algo));
			return;
		}
		if ("ECB".equals(mode)) {
			findings.add(finding(cls, ln, "ecb_mode", "high", transformation,
					"ECB mode is not semantically secure: " + transformation));
			return;
		}
		// A bare "AES" (or any block cipher) with no mode defaults to ECB on most providers.
		if (mode == null && ("AES".equals(algo) || "DESEDE".equals(algo) || "DES".equals(algo))) {
			findings.add(finding(cls, ln, "implicit_ecb", "high", transformation,
					"Transformation with no mode defaults to ECB: " + transformation));
			return;
		}
		findings.add(finding(cls, ln, "cipher", "info", transformation,
				"Cipher transformation: " + transformation));
	}

	private static Map<String, Object> finding(String cls, int line, String kind, String severity,
			String algorithm, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("algorithm", algorithm);
		f.put("className", cls);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "crypto-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new java.util.HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
