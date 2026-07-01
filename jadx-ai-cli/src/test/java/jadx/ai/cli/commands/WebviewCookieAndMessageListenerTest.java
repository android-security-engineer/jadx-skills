package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the WebView cookie-theft and modern-JS-bridge detections in {@link WebviewScanCommand}.
 *
 * <p>Two real WebView attack surfaces no detector covered: (1) {@code setAcceptThirdPartyCookies(true)} /
 * {@code setAcceptCookie(true)} + {@code CookieManager.getCookie} — web content (or MITM-injected JS)
 * exfiltrates the host app's session cookies (CWE-1004); (2) {@code addWebMessageListener} /
 * {@code WebMessageListener} — the post-API-23 two-way JS bridge that bypasses the addJavascriptInterface
 * rule, so a migrated bridge looked clean.
 */
class WebviewCookieAndMessageListenerTest {

	private static final Pattern LISTENER = WebviewScanCommand.WEB_MESSAGE_LISTENER;
	private static final Pattern COOKIE = WebviewScanCommand.THIRD_PARTY_COOKIE;
	private static final Pattern COOKIE_READ = WebviewScanCommand.COOKIE_READ;

	@Test
	void addWebMessageListenerFires() {
		assertTrue(LISTENER.matcher("webView.addWebMessageListener(new WebMessageListener() {").find(),
				"addWebMessageListener — modern JS bridge — must fire");
	}

	@Test
	void webViewCompatAddWebMessageListenerFires() {
		assertTrue(LISTENER.matcher("WebViewCompat.addWebMessageListener(webView, \"obj\", rules, listener);").find(),
				"WebViewCompat.addWebMessageListener must fire");
	}

	@Test
	void webMessageListenerTypeFires() {
		assertTrue(LISTENER.matcher("class MyBridge implements WebMessageListener {").find(),
				"a WebMessageListener type reference must fire");
	}

	@Test
	void onPostMessageWebMessageFires() {
		assertTrue(LISTENER.matcher("public void onPostMessage(WebMessage message, Uri origin) {").find(),
				"onPostMessage(WebMessage ...) override must fire");
	}

	@Test
	void setAcceptThirdPartyCookiesFires() {
		assertTrue(COOKIE.matcher("cookieManager.setAcceptThirdPartyCookies(webView, true);").find(),
				"setAcceptThirdPartyCookies(true) must fire");
	}

	@Test
	void setAcceptCookieFires() {
		assertTrue(COOKIE.matcher("cookieManager.setAcceptCookie(true);").find(),
				"setAcceptCookie(true) must fire");
	}

	@Test
	void cookieReadFires() {
		assertTrue(COOKIE_READ.matcher("String cookies = CookieManager.getInstance().getCookie(url);").find(),
				"CookieManager.getInstance().getCookie must fire");
	}

	@Test
	void disabledCookieDoesNotFire() {
		assertFalse(COOKIE.matcher("cookieManager.setAcceptThirdPartyCookies(webView, false);").find(),
				"setAcceptThirdPartyCookies(false) must NOT fire — cookies explicitly refused");
		assertFalse(COOKIE.matcher("cookieManager.setAcceptCookie(false);").find(),
				"setAcceptCookie(false) must NOT fire");
	}

	@Test
	void unrelatedCookieCallDoesNotFire() {
		assertFalse(COOKIE.matcher("cookieManager.setCookie(url, value);").find(),
				"setCookie (not setAcceptCookie) must NOT fire the accept-cookies rule");
	}
}
