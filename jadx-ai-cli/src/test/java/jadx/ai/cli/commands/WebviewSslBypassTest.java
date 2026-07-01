package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the class-level WebView TLS-bypass detection: an {@code onReceivedSslError} override that
 * calls {@code handler.proceed()} accepts any invalid certificate (MITM), while one that calls
 * {@code handler.cancel()} is correct and must not be flagged.
 */
class WebviewSslBypassTest {

	@Test
	void flagsProceedOnSslError() {
		String code = "public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError e) {\n"
				+ "    handler.proceed();\n"
				+ "}";
		assertTrue(WebviewScanCommand.hasSslBypass(code));
	}

	@Test
	void doesNotFlagCancelOnSslError() {
		String code = "public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError e) {\n"
				+ "    handler.cancel();\n"
				+ "}";
		assertFalse(WebviewScanCommand.hasSslBypass(code));
	}

	@Test
	void doesNotFlagProceedWithoutSslErrorContext() {
		// A proceed() call unrelated to SSL error handling must not trip the detector.
		String code = "void resume() { animation.proceed(); }";
		assertFalse(WebviewScanCommand.hasSslBypass(code));
	}
}
