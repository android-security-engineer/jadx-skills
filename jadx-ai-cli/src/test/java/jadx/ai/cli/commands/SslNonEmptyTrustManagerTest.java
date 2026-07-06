package jadx.ai.cli.commands;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the non-empty trust-all detection in {@link SslScanCommand}: a {@code checkServerTrusted}
 * that never throws and never delegates accepts every certificate even when its body is NOT the
 * literal {@code "{ }"} the {@code EMPTY_CHECK_*} regexes look for. The critical property is the
 * false-positive guard — a body that delegates to a real TrustManager, or throws, must NOT be
 * flagged, or every legitimate wrapping TrustManager would trip the highest-severity finding.
 */
class SslNonEmptyTrustManagerTest {

	private static final java.util.regex.Pattern SERVER =
			java.util.regex.Pattern.compile("checkServerTrusted\\s*\\([^)]*\\)");

	@Test
	void flagsReturnOnlyBody() {
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) { return; } }";
		List<Integer> hits = SslScanCommand.nonThrowingTrustBody(code, SERVER);
		assertEquals(1, hits.size(), "a bare `return;` body is trust-all");
	}

	@Test
	void flagsLogOnlyBody() {
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) {"
				+ " Log.d(\"tls\", \"accepting \" + a); } }";
		assertEquals(1, SslScanCommand.nonThrowingTrustBody(code, SERVER).size(),
				"a body that only logs but never throws/delegates is trust-all");
	}

	@Test
	void doesNotFlagDelegatingBody() {
		// Wrapping the platform TrustManager is SAFE — the delegate throws on a bad cert.
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) {"
				+ " this.defaultTm.checkServerTrusted(c, a); } }";
		assertTrue(SslScanCommand.nonThrowingTrustBody(code, SERVER).isEmpty(),
				"delegation to a real validator must not be flagged");
	}

	@Test
	void doesNotFlagThrowingBody() {
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) {"
				+ " if (c == null) throw new CertificateException(\"no chain\"); } }";
		assertTrue(SslScanCommand.nonThrowingTrustBody(code, SERVER).isEmpty(),
				"a body that throws does real validation");
	}

	@Test
	void skipsEmptyBodyToAvoidDoubleReport() {
		// EMPTY_CHECK_SERVER already reports "{ }"; this helper must stay silent on it.
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) { } }";
		assertTrue(SslScanCommand.nonThrowingTrustBody(code, SERVER).isEmpty(),
				"whitespace-only bodies are the EMPTY_CHECK_* regex's job");
	}

	@Test
	void matchBraceHonorsStringWithBraces() {
		//                  0123456789...
		String s = "{ String x = \"}\"; }";
		int close = SslScanCommand.matchBrace(s, 0);
		assertEquals(s.length() - 1, close, "a '}' inside a string literal must not close the block");
	}

	@Test
	void matchBraceHandlesNesting() {
		String s = "{ if (a) { b(); } }";
		assertEquals(s.length() - 1, SslScanCommand.matchBrace(s, 0));
	}

	@Test
	void doesNotFlagBodyThatVerifiesHostname() {
		String code = "class T { public void checkServerTrusted(X509Certificate[] c, String a) {"
				+ " hv.verify(host, session); } }";
		assertFalse(!SslScanCommand.nonThrowingTrustBody(code, SERVER).isEmpty(),
				"a verify(...) call counts as a validation signal");
	}
}
