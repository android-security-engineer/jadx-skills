package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code getAcceptedIssuers()} empty-return forms in {@link SslScanCommand#ACCEPTED_ISSUERS_NULL}.
 *
 * <p>A trust-all {@code X509TrustManager} almost always pairs an empty/throwing
 * {@code checkServerTrusted} with a {@code getAcceptedIssuers()} that returns null or an empty
 * array. The old rule matched only {@code return null} and {@code return new X509Certificate[0]}
 * — the sized-array form — but the empty-array-initializer idiom
 * {@code return new X509Certificate[]{};} is just as common a trust-all signature and was silently
 * missed.
 */
class SslAcceptedIssuersEmptyTest {

	private static final Pattern RULE = Pattern.compile(SslScanCommand.ACCEPTED_ISSUERS_NULL.pattern(), Pattern.DOTALL);

	private static boolean fires(String code) {
		return RULE.matcher(code).find();
	}

	@Test
	void returnNullStillFires() {
		assertTrue(fires("public X509Certificate[] getAcceptedIssuers() { return null; }"),
				"return null must still fire (regression guard)");
	}

	@Test
	void returnSizedZeroArrayFires() {
		assertTrue(fires("public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }"),
				"return new X509Certificate[0] must still fire (regression guard)");
	}

	@Test
	void returnEmptyArrayInitializerFires() {
		assertTrue(fires("public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }"),
				"return new X509Certificate[]{} — the empty-array-initializer trust-all idiom — must fire");
	}

	@Test
	void returnEmptyArrayInitializerWithSpaceFires() {
		assertTrue(fires("public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[] { }; }"),
				"the initializer form with internal spaces must fire");
	}

	@Test
	void returnRealIssuersDoesNotFire() {
		assertFalse(fires("public X509Certificate[] getAcceptedIssuers() { return this.issuers; }"),
				"a TrustManager that returns a real issuer array is not trust-all");
		assertFalse(fires("public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{ ca1, ca2 }; }"),
				"a non-empty issuer array is not trust-all");
	}
}
