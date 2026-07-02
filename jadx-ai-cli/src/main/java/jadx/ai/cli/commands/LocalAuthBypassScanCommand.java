package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Local-authentication bypass scanner — MASVS MSTG-AUTH-8.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code biometric-scan} (inventories BiometricPrompt / FingerprintManager
 * API usage and crypto object binding). This scanner focuses on <b>authentication logic bypass</b>:
 * methods that should enforce auth but instead return true unconditionally, use hardcoded
 * comparisons, or ignore the biometric authentication result in the callback.
 *
 * <p>Categories:
 * <ul>
 *   <li>{@code auth_returns_true} — A method with auth-related name (checkPassword/verifyPin/
 *       isAuthenticated/isVerified/validateCredentials/checkLogin) that contains
 *       {@code return true;} without any conditional logic — the auth check is a no-op</li>
 *   <li>{@code hardcoded_password} — A string comparison against a hardcoded literal in an
 *       auth method ({@code equals("...")} / {@code == "..."}) — trivially bypassable</li>
 *   <li>{@code biometric_result_ignored} — BiometricPrompt.AuthenticationCallback where
 *       {@code onAuthenticationSucceeded} is empty or does not use the {@code result} parameter,
 *       or where {@code onAuthenticationFailed} does not block access</li>
 *   <li>{@code empty_auth_method} — An auth-related method that is completely empty (no body
 *       beyond the return) — the check does nothing</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, bypassMethods, truncated}}.
 */
@Command(name = "local-auth-bypass-scan",
		description = "Detect local-authentication bypass patterns (MASVS MSTG-AUTH-8): auth methods returning true unconditionally, hardcoded password comparisons, BiometricPrompt callback ignoring result, empty auth methods. Distinct from biometric-scan (API usage inventory)")
public class LocalAuthBypassScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/**
	 * Gate: only scan classes that touch authentication logic. Kept in sync with {@link #AUTH_METHOD} —
	 * every AUTH_METHOD anchor must appear here or a class exercising only that anchor is skipped at the
	 * gate and the auth-bypass rules never fire (a silent high-severity FN). Previously missing
	 * {@code isUnlocked}/{@code isUserAuthenticated}/{@code isSessionValid}/{@code checkAuth}/
	 * {@code validateAuth}/{@code verifyAuth}/{@code isAuth} — a backdoor method
	 * {@code public boolean isUserAuthenticated() { return true; }} (no biometric/fingerprint reference)
	 * was skipped entirely, so {@code auth_returns_true} high was never reported. Package-private for testing.
	 */
	static final Pattern AUTH_MARKER = Pattern.compile(
			"checkPassword|verifyPin|isAuthenticated|isVerified|validateCredentials|checkLogin|"
					+ "BiometricPrompt|AuthenticationCallback|onAuthenticationSucceeded|onAuthenticationFailed|"
					+ "FingerprintManager|confirmCredential|checkSignature|verifySignature|"
					+ "isUnlocked|isAuth|verifyAuth|checkAuth|validateAuth|isUserAuthenticated|isSessionValid");

	/** Method names that suggest an auth check. */
	private static final Pattern AUTH_METHOD = Pattern.compile(
			"(checkPassword|verifyPin|isAuthenticated|isVerified|validateCredentials|checkLogin|"
					+ "confirmCredential|checkSignature|verifySignature|isUnlocked|isAuth|verifyAuth|"
					+ "checkAuth|validateAuth|isUserAuthenticated|isSessionValid)");

	/** Return true without condition. */
	private static final Pattern RETURN_TRUE = Pattern.compile("return\\s+true\\s*;");

	/** Hardcoded string comparison in auth context. */
	private static final Pattern HARDCODED_COMPARE = Pattern.compile(
			"\\.equals\\s*\\(\\s*\"[^\"]+\"\\s*\\)|\"[^\"]+\"\\s*\\.equals|==\\s*\"[^\"]+\"|\"[^\"]+\"\\s*==");

	/** BiometricPrompt callback patterns. */
	private static final Pattern ON_AUTH_SUCCEEDED = Pattern.compile("onAuthenticationSucceeded");
	static final Pattern ON_AUTH_FAILED = Pattern.compile("onAuthenticationFailed");
	private static final Pattern USES_RESULT = Pattern.compile(
			"result\\.|result\\)|CryptoObject|authenticationResult");

	/**
	 * A call that blocks access from a failed-auth callback — {@code finish()}/{@code return}/
	 * {@code cancel()}/{@code disable()}/{@code System.exit}/{@code throw}. Its <b>absence</b> from an
	 * {@code onAuthenticationFailed} body is the "failed callback does not block access" half of
	 * {@code biometric_result_ignored}. Package-private for testing.
	 */
	static final Pattern BLOCKING_CALL = Pattern.compile(
			"\\bfinish\\s*\\(|\\breturn\\b|\\bcancel\\s*\\(|\\bdisable\\s*\\(|System\\.exit\\s*\\(|\\bthrow\\s");

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
		TreeSet<String> bypassMethods = new TreeSet<>();

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
			if (code == null || code.isEmpty() || !AUTH_MARKER.matcher(code).find()) {
				continue;
			}

			boolean reportedFailedCallback = false;

			// Scan for auth-related methods
			String[] lines = code.split("\n", -1);
			int methodStartLine = -1;
			String methodKind = null;
			int braceDepth = 0;
			boolean inAuthMethod = false;
			boolean methodHasCondition = false;
			boolean methodHasReturnTrue = false;
			boolean methodHasHardcodedCompare = false;
			int methodBodyLines = 0;

			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				String trimmed = line.trim();

				// Detect method start
				Matcher authMethodMatcher = AUTH_METHOD.matcher(line);
				if (authMethodMatcher.find() && line.contains("(") && !inAuthMethod) {
					methodStartLine = i + 1;
					methodKind = authMethodMatcher.group(1);
					inAuthMethod = true;
					methodHasCondition = false;
					methodHasReturnTrue = false;
					methodHasHardcodedCompare = false;
					methodBodyLines = 0;
					braceDepth = 0;
					// Count opening braces on this line
					braceDepth += countChar(line, '{') - countChar(line, '}');
					continue;
				}

				if (inAuthMethod) {
					methodBodyLines++;
					braceDepth += countChar(line, '{') - countChar(line, '}');

					// Check for conditional logic
					if (trimmed.startsWith("if ") || trimmed.startsWith("if(") || trimmed.contains("else ")
							|| trimmed.contains("switch(") || trimmed.startsWith("switch ")) {
						methodHasCondition = true;
					}

					// Check for return true
					if (RETURN_TRUE.matcher(line).find()) {
						methodHasReturnTrue = true;
					}

					// Check for hardcoded comparison
					if (HARDCODED_COMPARE.matcher(line).find()) {
						methodHasHardcodedCompare = true;
					}

					// Method end
					if (braceDepth <= 0 && methodBodyLines > 0) {
						// Analyze the completed method
						if (methodHasReturnTrue && !methodHasCondition) {
							String sig = fullName + "." + methodKind;
							bypassMethods.add(sig);
							findings.add(finding("auth_returns_true", "high", fullName, methodStartLine,
									"Auth method " + methodKind + "() returns true unconditionally — "
											+ "the authentication check is a no-op; any caller bypasses auth"));
							highSeverityCount++;
						} else if (methodHasHardcodedCompare && methodKind != null) {
							String sig = fullName + "." + methodKind;
							bypassMethods.add(sig);
							findings.add(finding("hardcoded_password", "high", fullName, methodStartLine,
									"Auth method " + methodKind + "() compares against a hardcoded string — "
											+ "trivially bypassable by inspecting the APK or using a static value"));
							highSeverityCount++;
						} else if (methodBodyLines <= 2 && methodKind != null) {
							// Very short method body (likely just return true/false)
							String sig = fullName + "." + methodKind;
							bypassMethods.add(sig);
							findings.add(finding("empty_auth_method", "medium", fullName, methodStartLine,
									"Auth method " + methodKind + "() has an empty or trivial body — "
											+ "the check likely does nothing meaningful"));
						}

						inAuthMethod = false;
						methodKind = null;
					}
				}

				// BiometricPrompt callback analysis
				if (ON_AUTH_SUCCEEDED.matcher(line).find()) {
					// Check if the next few lines use the result parameter
					boolean usesResult = false;
					for (int j = i + 1; j < Math.min(i + 10, lines.length); j++) {
						if (USES_RESULT.matcher(lines[j]).find()) {
							usesResult = true;
							break;
						}
						// Stop at next method or closing brace
						if (lines[j].contains("void onAuthentication") || lines[j].trim().equals("}")) {
							break;
						}
					}
					if (!usesResult) {
						findings.add(finding("biometric_result_ignored", "medium", fullName, i + 1,
								"onAuthenticationSucceeded callback does not use the authentication result — "
										+ "the biometric check may be cosmetic; verify the callback actually "
										+ "enforces access based on the result"));
					}
				}

				// onAuthenticationFailed that does not block access — the second half of
				// biometric_result_ignored promised in the class javadoc. ON_AUTH_FAILED was defined but
				// never wired in; a failed-auth callback that does not finish()/return/cancel lets the
				// user past the biometric check. Scan the callback body (until the next method/closing
				// brace) for a blocking call; fire if none is found.
				if (!reportedFailedCallback && ON_AUTH_FAILED.matcher(line).find()) {
					boolean blocks = false;
					for (int j = i + 1; j < Math.min(i + 12, lines.length); j++) {
						String bodyLine = lines[j];
						if (BLOCKING_CALL.matcher(bodyLine).find()) {
							blocks = true;
							break;
						}
						// End of callback body — next callback method or closing brace at method scope.
						if (bodyLine.contains("void onAuthentication") || bodyLine.trim().equals("}")) {
							break;
						}
					}
					if (!blocks) {
						findings.add(finding("biometric_result_ignored", "medium", fullName, i + 1,
								"onAuthenticationFailed callback does not block access (no finish()/return/"
										+ "cancel()) — a failed biometric check does not stop the flow; "
										+ "call finish() or deny the action in the failure callback"));
						reportedFailedCallback = true;
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("bypassMethods", new ArrayList<>(bypassMethods));
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static int countChar(String s, char c) {
		int count = 0;
		for (int i = 0; i < s.length(); i++) {
			if (s.charAt(i) == c) count++;
		}
		return count;
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
		return "local-auth-bypass-scan";
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
