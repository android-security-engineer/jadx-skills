package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;

/**
 * Scans decompiled code and text resources for hardcoded secrets (API keys, tokens, private
 * keys, credentials) using a curated pattern set plus a Shannon-entropy filter for generic
 * high-entropy string literals. Pattern library absorbed from mobile-security-mcp.
 */
@Command(name = "secrets-scan", description = "Scan code and resources for hardcoded secrets and credentials")
public class SecretsScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--min-entropy" }, description = "Min Shannon entropy for generic secret detection", defaultValue = "3.5")
	protected double minEntropy = 3.5;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** A named secret pattern. */
	private static final class Rule {
		final String kind;
		final Pattern pattern;
		final String confidence;

		Rule(String kind, String regex, String confidence) {
			this.kind = kind;
			this.pattern = Pattern.compile(regex);
			this.confidence = confidence;
		}
	}

	// Quote character class: matches ' or " — built via concatenation to avoid Java literal issues
	private static final String Q = "[\\Q'" + "\"" + "\\E]";

	private static final List<Rule> RULES = List.of(
			// Cloud provider keys
			new Rule("aws_access_key", "AKIA[0-9A-Z]{16}", "high"),
			new Rule("aws_secret_key", "(?i)(?:aws.?secret|secret.?access.?key)[" + "'" + "\"" + ":\\\\s=]+" + Q + "?([A-Za-z0-9/+=]{40})" + Q + "?", "high"),
			new Rule("google_api_key", "AIza[0-9A-Za-z_\\-]{35}", "high"),
			new Rule("google_oauth_id", "[0-9]{12}-[a-z0-9]{32}\\.apps\\.googleusercontent\\.com", "medium"),
			new Rule("firebase_url", "https?://[a-z0-9][a-z0-9\\-]{1,61}(?:-default-rtdb)?\\.firebaseio\\.com", "high"),
			new Rule("firebase_storage", "[a-z0-9][a-z0-9\\-]{3,62}\\.appspot\\.com", "medium"),
			new Rule("gcp_storage_url", "https?://storage\\.googleapis\\.com/[a-z0-9\\-._/]{3,}", "medium"),
			// Payment processor keys
			new Rule("stripe_secret_key", "sk_(?:live|test)_[0-9a-zA-Z]{24,}", "high"),
			new Rule("stripe_publishable_key", "pk_(?:live|test)_[0-9a-zA-Z]{24,}", "medium"),
			// Communication / messaging keys
			new Rule("slack_token", "xox[baprs]-[0-9A-Za-z\\-]{10,48}", "high"),
			new Rule("sendgrid_key", "SG\\.[a-zA-Z0-9_\\-]{22}\\.[a-zA-Z0-9_\\-]{43}", "high"),
			new Rule("twilio_account_sid", "AC[0-9a-fA-F]{32}", "high"),
			new Rule("twilio_key_sid", "SK[0-9a-fA-F]{32}", "high"),
			// Developer platform tokens
			new Rule("github_token", "gh[pousr]_[0-9A-Za-z_]{36,}", "high"),
			new Rule("mapbox_token", "pk\\.eyJ1[A-Za-z0-9_\\-]{60,}", "medium"),
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

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("minEntropy")) {
			this.minEntropy = ((Number) args.get("minEntropy")).doubleValue();
		}
		if (args.containsKey("includeResources")) {
			this.includeResources = Boolean.TRUE.equals(args.get("includeResources"));
		}
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
			scanText(code, fullName, "code", findings);
		}

		if (includeResources && findings.size() < limit) {
			scanResources(decompiler, findings);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private void scanResources(JadxDecompiler decompiler, List<Map<String, Object>> findings) {
		for (ResourceFile res : decompiler.getResources()) {
			if (findings.size() >= limit) {
				break;
			}
			ResourceType type = res.getType();
			if (type != ResourceType.XML && type != ResourceType.ARSC && type != ResourceType.MANIFEST) {
				continue;
			}
			try {
				var container = res.loadContent();
				if (container == null) {
					continue;
				}
				var codeInfo = container.getText();
				if (codeInfo != null) {
					scanText(codeInfo.toString(), res.getOriginalName(), "resource", findings);
				}
			} catch (Exception ignored) {
				// skip unreadable resources
			}
		}
	}

	private void scanText(String text, String source, String origin, List<Map<String, Object>> findings) {
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
			// Entropy-based generic detection on long quoted literals.
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

	private static Map<String, Object> finding(String kind, String value, String source, String origin,
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
	static String redact(String value) {
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
	private static boolean looksRandom(String s) {
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

	static double shannonEntropy(String s) {
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

	@Override
	protected String getDaemonCommandName() {
		return "secrets-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new java.util.HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("minEntropy", minEntropy);
		args.put("includeResources", includeResources);
		args.put("limit", limit);
		return args;
	}
}
