package jadx.ai.cli.commands;

import java.util.List;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the try/catch-swallow trust-all detection in {@link SslScanCommand#nonThrowingTrustBody}.
 *
 * <p>A {@code checkServerTrusted} body that <em>appears</em> to validate — it calls
 * {@code checkValidity()} (a {@code VALIDATION_SIGNAL}) — but wraps the call in a {@code try} whose
 * {@code catch} swallows the {@code CertificateException} is a real bypass: the "validation" never
 * rejects. {@code VALIDATION_SIGNAL} alone misreads it as safe. The detector now flags it: a body
 * with a {@code catch} but no bare {@code throw} is a swallow-and-trust-all.
 *
 * <p>jadx optimises a re-throwing {@code catch{throw e}} away (the call is emitted without a catch),
 * so the {@code catch + no-throw} signal is specific to the swallow form and does not trip a genuine
 * re-throwing handler.
 */
class SslSwallowCatchTrustManagerTest {

	private static final Pattern SERVER =
			Pattern.compile("checkServerTrusted\\s*\\([^)]*\\)");

	@Test
	void flagsTryCatchSwallowWithCheckValidity() {
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) {"
				+ " try { c[0].checkValidity(); } catch (CertificateException unused) { } } }";
		List<Integer> hits = SslScanCommand.nonThrowingTrustBody(code, SERVER);
		assertEquals(1, hits.size(),
				"a checkValidity wrapped in an empty catch swallows the rejection — trust-all");
	}

	@Test
	void flagsTryCatchSwallowWithVerifyCall() {
		// A verify() call (VALIDATION_SIGNAL) wrapped in a try whose catch only logs — no bare throw
		// anywhere in the body, so the catch swallows whatever verify raises.
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) {"
				+ " try { hv.verify(host, session); } catch (Exception e) { Log.d(\"tls\", \"ignoring\"); } } }";
		assertEquals(1, SslScanCommand.nonThrowingTrustBody(code, SERVER).size(),
				"a verify() call wrapped in a non-throwing catch is a swallow — trust-all");
	}

	@Test
	void doesNotFlagRethrowingCatch() {
		// A genuine re-throw: the catch re-throws, so rejection propagates. Body has catch + a bare throw.
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) {"
				+ " try { c[0].checkValidity(); } catch (CertificateException e) { throw e; } } }";
		assertTrue(SslScanCommand.nonThrowingTrustBody(code, SERVER).isEmpty(),
				"a catch that re-throws propagates rejection — must NOT be flagged");
	}

	@Test
	void doesNotFlagThrowWithoutCatch() {
		// Throw present, no catch — already covered by the original signal logic, but confirms the new
		// branch doesn't regress it.
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) {"
				+ " if (c == null) throw new CertificateException(); } }";
		assertTrue(SslScanCommand.nonThrowingTrustBody(code, SERVER).isEmpty(),
				"a body that throws without any catch must NOT be flagged");
	}

	@Test
	void doesNotFlagDelegatingBodyWithoutCatch() {
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) {"
				+ " this.defaultTm.checkServerTrusted(c, a); } }";
		assertTrue(SslScanCommand.nonThrowingTrustBody(code, SERVER).isEmpty(),
				"a delegating body with no catch must NOT be flagged");
	}
}
