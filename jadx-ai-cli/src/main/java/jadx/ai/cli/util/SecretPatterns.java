package jadx.ai.cli.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Curated hardcoded-secret pattern library plus a Shannon-entropy generic detector — the single
 * source of truth shared by {@code secrets-scan} (Java code + XML/ARSC/manifest text) and
 * {@code native-libs} (printable strings carved out of {@code lib/<abi>/*.so}). Keys are routinely
 * moved into JNI / native code precisely to escape Java-level scanners, so the same signature set
 * must run on both sides.
 *
 * <p>Findings share one shape: {@code {kind, match(redacted), source, origin, lineNumber,
 * confidence[, entropy]}}. Pattern library absorbed from mobile-security-mcp.
 */
public final class SecretPatterns {

	private SecretPatterns() {
	}

	/** A named secret pattern. */
	public static final class Rule {
		public final String kind;
		public final Pattern pattern;
		public final String confidence;

		Rule(String kind, String regex, String confidence) {
			this.kind = kind;
			this.pattern = Pattern.compile(regex);
			this.confidence = confidence;
		}
	}

	// Quote character class: matches ' or " — built via concatenation to avoid Java literal issues.
	private static final String Q = "[\\Q'" + "\"" + "\\E]";

	public static final List<Rule> RULES = List.of(
			// Cloud provider keys
			new Rule("aws_access_key", "AKIA[0-9A-Z]{16}", "high"),
			new Rule("aws_secret_key", "(?i)(?:aws.?secret|secret.?access.?key)[" + "'" + "\"" + ":\\\\s=]+" + Q + "?([A-Za-z0-9/+=]{40})" + Q + "?", "high"),
			new Rule("azure_storage_account_key", "AccountKey[" + "'" + "\"" + "\\\\s:=]+" + Q + "?([A-Za-z0-9+/]{86,}={0,2})" + Q + "?", "high"),
			new Rule("google_api_key", "AIza[0-9A-Za-z_\\-]{35}", "high"),
			new Rule("google_oauth_id", "[0-9]{12}-[a-z0-9]{32}\\.apps\\.googleusercontent\\.com", "medium"),
			new Rule("firebase_url", "https?://[a-z0-9][a-z0-9\\-]{1,61}(?:-default-rtdb)?\\.firebaseio\\.com", "high"),
			new Rule("firebase_storage", "[a-z0-9][a-z0-9\\-]{3,62}\\.appspot\\.com", "medium"),
			new Rule("gcp_storage_url", "https?://storage\\.googleapis\\.com/[a-z0-9\\-._/]{3,}", "medium"),
			// Payment processor keys
			new Rule("stripe_secret_key", "(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}", "high"),
			new Rule("stripe_publishable_key", "pk_(?:live|test)_[0-9a-zA-Z]{24,}", "medium"),
			// Communication / messaging keys
			new Rule("slack_token", "xox[baprs]-[0-9A-Za-z\\-]{10,48}", "high"),
			new Rule("sendgrid_key", "SG\\.[a-zA-Z0-9_\\-]{22}\\.[a-zA-Z0-9_\\-]{43}", "high"),
			new Rule("twilio_account_sid", "AC[0-9a-fA-F]{32}", "high"),
			new Rule("twilio_key_sid", "SK[0-9a-fA-F]{32}", "high"),
			// Developer platform tokens
			new Rule("github_token", "gh[pousr]_[0-9A-Za-z_]{36,}", "high"),
			new Rule("github_fine_grained_pat", "github_pat_[0-9A-Za-z_]{82,}", "high"),
			new Rule("mapbox_token", "pk\\.eyJ1[A-Za-z0-9_\\-]{60,}", "medium"),
			new Rule("google_oauth_client_secret", "GOCSPX-[0-9A-Za-z_\\-]{24,}", "high"),
			// Authentication tokens
			new Rule("jwt", "eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}", "medium"),
			new Rule("basic_auth", "Basic [A-Za-z0-9+/]{20,}={0,2}", "high"),
			new Rule("google_oauth_token", "ya29\\.[0-9A-Za-z_\\-]+", "medium"),
			// Cryptographic material
			new Rule("rsa_private_key", "-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "high"),
			// Generic credential patterns (lower confidence)
			new Rule("generic_secret_assign",
					"(?i)(?:api[_-]?key|secret|passwd|password|token|auth|access[_-]?token)[" + "'" + "\"" + "\\\\s:=]{1,4}" + Q + "([0-9A-Za-z_\\-./+!@#$%^&*]{8,})" + Q, "low"),
			new Rule("generic_password_field",
					"(?i)(?:password|passwd|pwd|pass)\\s*[=:]\\s*" + Q + "([^" + "'" + "\"" + "]{6,})" + Q, "low"));

	// Quoted string literal, used for the entropy-based generic detector.
	private static final Pattern STRING_LITERAL = Pattern.compile("\"([0-9A-Za-z_\\-./+=]{20,})\"");

	/**
	 * Scan one text blob line-by-line, appending findings. Runs the full rule set plus the
	 * quoted-literal entropy detector (set {@code minEntropy <= 0} to disable the entropy pass).
	 */
	public static void scanText(String text, String source, String origin, double minEntropy,
			int limit, List<Map<String, Object>> findings) {
		if (text == null) {
			return;
		}
		String[] lines = text.split("\n", -1);
		for (int i = 0; i < lines.length; i++) {
			if (findings.size() >= limit) {
				return;
			}
			String line = lines[i];
			for (Rule rule : RULES) {
				Matcher m = rule.pattern.matcher(line);
				while (m.find() && findings.size() < limit) {
					String hit = m.groupCount() >= 1 && m.group(1) != null ? m.group(1) : m.group(0);
					findings.add(finding(rule.kind, hit, source, origin, i + 1, rule.confidence));
				}
			}
			if (minEntropy > 0) {
				Matcher sm = STRING_LITERAL.matcher(line);
				while (sm.find() && findings.size() < limit) {
					String literal = sm.group(1);
					double entropy = shannonEntropy(literal);
					if (entropy >= minEntropy && looksRandom(literal)) {
						Map<String, Object> f = finding("high_entropy_string", literal, source, origin, i + 1, "low");
						f.put("entropy", Math.round(entropy * 100.0) / 100.0);
						findings.add(f);
					}
				}
			}
		}
	}

	/**
	 * Scan already-extracted strings (e.g. carved out of a native {@code .so}). Each string is its
	 * own unit; {@code lineNumber} is its 1-based index in the list. Only the curated rule set runs
	 * — the quoted-literal entropy detector is skipped because native binaries have no source
	 * quoting and are noisy. Returns findings in the same shape as {@link #scanText}.
	 */
	public static void scanStrings(List<String> strings, String source, String origin, int limit,
			List<Map<String, Object>> findings) {
		if (strings == null) {
			return;
		}
		for (int i = 0; i < strings.size(); i++) {
			if (findings.size() >= limit) {
				return;
			}
			String s = strings.get(i);
			for (Rule rule : RULES) {
				Matcher m = rule.pattern.matcher(s);
				while (m.find() && findings.size() < limit) {
					String hit = m.groupCount() >= 1 && m.group(1) != null ? m.group(1) : m.group(0);
					findings.add(finding(rule.kind, hit, source, origin, i + 1, rule.confidence));
				}
			}
		}
	}

	public static Map<String, Object> finding(String kind, String value, String source, String origin,
			int line, String confidence) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("match", redact(value));
		f.put("source", source);
		f.put("origin", origin);
		f.put("lineNumber", line);
		f.put("confidence", confidence);
		return f;
	}

	/** Mask the middle of a secret, keeping a short prefix/suffix for identification. */
	public static String redact(String value) {
		if (value == null) {
			return null;
		}
		int n = value.length();
		if (n <= 8) {
			return value.charAt(0) + "****";
		}
		return value.substring(0, 4) + "****" + value.substring(n - 2);
	}

	/** Heuristic: a value is "random looking" if it mixes character classes. */
	public static boolean looksRandom(String s) {
		boolean hasUpper = false;
		boolean hasLowerOrDigit = false;
		for (char c : s.toCharArray()) {
			if (Character.isUpperCase(c)) {
				hasUpper = true;
			} else if (Character.isLowerCase(c) || Character.isDigit(c)) {
				hasLowerOrDigit = true;
			}
		}
		return hasUpper && hasLowerOrDigit;
	}

	public static double shannonEntropy(String s) {
		if (s == null || s.isEmpty()) {
			return 0;
		}
		int[] freq = new int[256];
		int counted = 0;
		for (char c : s.toCharArray()) {
			if (c < 256) {
				freq[c]++;
				counted++;
			}
		}
		double entropy = 0;
		for (int f : freq) {
			if (f > 0) {
				double p = (double) f / counted;
				entropy -= p * (Math.log(p) / Math.log(2));
			}
		}
		return entropy;
	}

	// Convenience list-returning wrappers.
	public static List<Map<String, Object>> scanStrings(List<String> strings, String source, String origin, int limit) {
		List<Map<String, Object>> out = new ArrayList<>();
		scanStrings(strings, source, origin, limit, out);
		return out;
	}
}
