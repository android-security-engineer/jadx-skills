package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the gate-vs-rule symmetry fix in {@link WebviewScanCommand#WEBVIEW_MARKER}.
 *
 * <p>The gate lacked {@code CookieManager}. A session/cookie-manager class that reads the WebView
 * cookie jar via {@code CookieManager.getInstance().getCookie(url)} — to forward over its own network
 * stack or log — has no {@code WebView}/{@code WebSettings}/{@code WebViewClient}/{@code WebChromeClient}
 * token, so it was skipped at the gate → {@code cookie_read} medium never fired. Verified against real
 * javac&#8594;d8&#8594;jadx output.
 */
class WebviewGateCookieManagerTest {

	private static final java.util.regex.Pattern WEBVIEW_MARKER = WebviewScanCommand.WEBVIEW_MARKER;

	@Test
	void cookieManagerGetInstanceMatchesGate() {
		assertTrue(WEBVIEW_MARKER.matcher(
				"return CookieManager.getInstance().getCookie(url);").find(),
				"a CookieManager.getInstance().getCookie() class — no WebView token — must match the gate (was skipped → cookie_read FN)");
	}

	@Test
	void cookieManagerImportMatchesGate() {
		assertTrue(WEBVIEW_MARKER.matcher("import android.webkit.CookieManager;").find(),
				"a CookieManager import must match the gate");
	}

	@Test
	void webViewStillMatchesGate() {
		assertTrue(WEBVIEW_MARKER.matcher("WebView webView = new WebView(this);").find(),
				"a WebView reference must still match the gate");
	}
}
