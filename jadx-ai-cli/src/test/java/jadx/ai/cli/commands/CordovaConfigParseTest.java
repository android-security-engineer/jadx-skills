package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the Cordova hybrid-app triage: the config.xml whitelist wildcard/cleartext classifiers and
 * the index.html CSP extraction/unsafe check — the two controls that decide whether a compromised
 * page can pivot into native plugins.
 */
class CordovaConfigParseTest {

	@Test
	void wildcardWhitelistValuesAreFlagged() {
		assertTrue(CordovaAnalysisCommand.isWildcard("*"));
		assertTrue(CordovaAnalysisCommand.isWildcard("*://*"));
		assertTrue(CordovaAnalysisCommand.isWildcard("https://*"));
	}

	@Test
	void scopedWhitelistValuesAreNotWildcards() {
		assertFalse(CordovaAnalysisCommand.isWildcard("https://api.example.com"));
		assertFalse(CordovaAnalysisCommand.isWildcard("*.example.com"));
	}

	@Test
	void cleartextWhitelistIsDistinctFromWildcard() {
		assertTrue(CordovaAnalysisCommand.isCleartext("http://api.example.com"));
		assertFalse(CordovaAnalysisCommand.isCleartext("https://api.example.com"));
		// a bare http wildcard is a wildcard, not merely cleartext
		assertFalse(CordovaAnalysisCommand.isCleartext("http://*"));
	}

	@Test
	void cspIsExtractedFromMetaTag() {
		String html = "<html><head>"
				+ "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self'\">"
				+ "</head></html>";
		assertEquals("default-src 'self'; script-src 'self'", CordovaAnalysisCommand.cspContent(html));
	}

	@Test
	void missingCspReturnsNull() {
		assertNull(CordovaAnalysisCommand.cspContent("<html><head></head><body></body></html>"));
	}

	@Test
	void unsafeCspIsDetected() {
		assertTrue(CordovaAnalysisCommand.cspIsUnsafe("default-src 'self'; script-src 'self' 'unsafe-inline'"));
		assertTrue(CordovaAnalysisCommand.cspIsUnsafe("script-src 'unsafe-eval'"));
		assertTrue(CordovaAnalysisCommand.cspIsUnsafe("default-src *"));
	}

	@Test
	void strictCspIsNotUnsafe() {
		assertFalse(CordovaAnalysisCommand.cspIsUnsafe("default-src 'self'; script-src 'self'; object-src 'none'"));
		// a wildcard host is scoped, not a bare "*" source
		assertFalse(CordovaAnalysisCommand.cspIsUnsafe("default-src 'self' *.example.com"));
	}
}
