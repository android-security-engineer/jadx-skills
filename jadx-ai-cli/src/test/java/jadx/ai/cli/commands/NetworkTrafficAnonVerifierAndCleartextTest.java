package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the deepened detection in {@link NetworkTrafficScanCommand}.
 *
 * <p>Covers three real-world false negatives found by auditing the scanner against jadx-decompiled
 * forms:
 * <ul>
 *   <li><b>Anonymous {@code HostnameVerifier} returning true</b> — the old {@code ALLOW_ALL_VERIFIER}
 *       third arm {@code HostnameVerifier\s*\{.*return\s+true} was <em>dead code</em>: it required
 *       {@code \{} to follow {@code HostnameVerifier} immediately, but Java/jadx syntax is
 *       {@code new HostnameVerifier()} with a parameter list. Now matched at class scope (DOTALL) by
 *       {@link NetworkTrafficScanCommand#ANON_HOSTNAME_VERIFIER_TRUE}, which requires the parameter
 *       list so a real verifier does not fire.</li>
 *   <li><b>Bare {@code "http://"} scheme</b> — {@code HTTP_URL} only matched complete
 *       {@code "http://..."} literals, so {@code "http://" + host} was missed. Now
 *       {@link NetworkTrafficScanCommand#HTTP_URL_BARE} catches the concatenated/constant form.</li>
 *   <li><b>{@code ConnectionSpec.CLEARTEXT}</b> — an explicit OkHttp cleartext-only spec. The
 *       {@code connectionSpecs} token was treated as a safe TLS signal, suppressing the report.
 *       Now {@link NetworkTrafficScanCommand#CLEARTEXT_SPEC} is its own independent rule.</li>
 * </ul>
 */
class NetworkTrafficAnonVerifierAndCleartextTest {

	private static final java.util.regex.Pattern ANON_HV = NetworkTrafficScanCommand.ANON_HOSTNAME_VERIFIER_TRUE;
	private static final java.util.regex.Pattern BARE_HTTP = NetworkTrafficScanCommand.HTTP_URL_BARE;
	private static final java.util.regex.Pattern CLEARTEXT = NetworkTrafficScanCommand.CLEARTEXT_SPEC;

	// --- Anonymous HostnameVerifier returning true ---

	@Test
	void anonHostnameVerifierReturnTrueFiresAcrossLines() {
		// jadx decompiles an anonymous HostnameVerifier across multiple lines — DOTALL match.
		String code = "HostnameVerifier verifier = new HostnameVerifier() {\n"
				+ "    @Override\n"
				+ "    public boolean verify(String hostname, SSLSession session) {\n"
				+ "        return true;\n"
				+ "    }\n"
				+ "};\n";
		assertTrue(ANON_HV.matcher(code).find(),
				"an anonymous HostnameVerifier with a return-true body must fire (DOTALL, multi-line)");
	}

	@Test
	void anonHostnameVerifierSingleLineFires() {
		assertTrue(ANON_HV.matcher("new HostnameVerifier() { public boolean verify(...) { return true; } };").find(),
				"single-line anonymous HostnameVerifier return-true must fire");
	}

	@Test
	void realHostnameVerifierDoesNotFire() {
		// A real verifier returns the result of a comparison, not a bare true.
		assertFalse(ANON_HV.matcher("new HostnameVerifier() {\n"
				+ "    public boolean verify(String host, SSLSession s) {\n"
				+ "        return host.equals(expected);\n"
				+ "    }\n"
				+ "};").find(),
				"a verifier that returns a comparison (not bare true) must NOT fire");
	}

	@Test
	void oldDeadCodeArmDidNotRequireParameterList() {
		// The OLD arm `HostnameVerifier\s*\{.*return true` would NOT match this (no '{' after
		// HostnameVerifier — there is a '(' parameter list first). The new pattern matches it.
		assertFalse(java.util.regex.Pattern.compile("HostnameVerifier\\s*\\{.*return\\s+true").matcher(
				"new HostnameVerifier() { return true; }").find(),
				"the OLD dead-code arm must NOT match (proves it was dead); the new pattern does");
		assertTrue(ANON_HV.matcher("new HostnameVerifier() { return true; }").find(),
				"the new pattern matches where the old arm failed");
	}

	// --- Bare "http://" scheme ---

	@Test
	void bareHttpSchemeConcatenatedFires() {
		assertTrue(BARE_HTTP.matcher("String url = \"http://\" + host;").find(),
				"\"http://\" + host concatenation must fire");
	}

	@Test
	void bareHttpSchemeConcatFires() {
		assertTrue(BARE_HTTP.matcher("String url = \"http://\".concat(host);").find(),
				"\"http://\".concat(host) must fire");
	}

	@Test
	void bareHttpSchemeConstantFires() {
		assertTrue(BARE_HTTP.matcher("String SCHEME = \"http://\";").find(),
				"a \"http://\" constant assignment must fire");
	}

	@Test
	void fullHttpUrlDoesNotDoubleFireBare() {
		// A complete "http://example.com" literal is the job of HTTP_URL, not HTTP_URL_BARE.
		// The bare pattern matches `"http://"+` / `.concat` / `="http://"`, none of which appear here.
		assertFalse(BARE_HTTP.matcher("String url = \"http://example.com\";").find(),
				"a complete http:// URL literal must not fire the bare-scheme rule (HTTP_URL handles it)");
	}

	// --- ConnectionSpec.CLEARTEXT ---

	@Test
	void cleartextSpecFires() {
		assertTrue(CLEARTEXT.matcher(".connectionSpecs(Arrays.asList(ConnectionSpec.CLEARTEXT))").find(),
				"ConnectionSpec.CLEARTEXT must fire the cleartext-spec rule");
	}

	@Test
	void cleartextSpecBuilderFires() {
		assertTrue(CLEARTEXT.matcher("specs.add(ConnectionSpec.CLEARTEXT);").find(),
				"ConnectionSpec.CLEARTEXT added to a spec list must fire");
	}

	@Test
	void cleartextAndTlsDoesNotFire() {
		// CLEARTEXT_AND_TLS is the safe fallback spec (permits both); only the CLEARTEXT-only
		// constant should fire.
		assertFalse(CLEARTEXT.matcher("ConnectionSpec.CLEARTEXT_AND_TLS").find(),
				"ConnectionSpec.CLEARTEXT_AND_TLS must NOT fire (only the CLEARTEXT-only constant)");
	}

	@Test
	void cleartextSpecWordBoundaryNotFooled() {
		// Ensure the pattern is anchored on ConnectionSpec.CLEARTEXT, not a loose 'CLEARTEXT' token.
		assertFalse(CLEARTEXT.matcher("boolean CLEARTEXT_ENABLED = true;").find(),
				"a bare CLEARTEXT variable must NOT fire (must be ConnectionSpec.CLEARTEXT)");
	}
}
