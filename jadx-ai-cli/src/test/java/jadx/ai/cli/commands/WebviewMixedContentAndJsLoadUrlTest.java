package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards two real-world false negatives in {@link WebviewScanCommand}, both verified against actual
 * javac&#8594;d8&#8594;jadx decompiled output.
 *
 * <ul>
 *   <li><b>{@code mixed_content}</b> — the old rule matched the {@code MIXED_CONTENT_ALWAYS_ALLOW}
 *       identifier, but {@code WebSettings} interface constants are compile-time-folded to integer
 *       literals in the bytecode; jadx decompiles the call as {@code setMixedContentMode(0)}
 *       (value 0 == ALWAYS_ALLOW) with NO identifier, so the old pattern never matched any real
 *       input. {@link WebviewScanCommand#MIXED_CONTENT_ALWAYS_ALLOW} now matches the literal 0.</li>
 *   <li><b>{@code js_loadurl}</b> — the cleartext-load rules only covered the {@code http://} scheme;
 *       {@code loadUrl("javascript:...")} — the most common WebView JS-injection / UXSS surface —
 *       was missed. {@link WebviewScanCommand#JS_LOAD_URL} now matches it.</li>
 * </ul>
 */
class WebviewMixedContentAndJsLoadUrlTest {

	private static final java.util.regex.Pattern MIXED = WebviewScanCommand.MIXED_CONTENT_ALWAYS_ALLOW;
	private static final java.util.regex.Pattern JS_URL = WebviewScanCommand.JS_LOAD_URL;

	// --- mixed_content: jadx folds MIXED_CONTENT_ALWAYS_ALLOW to literal 0 ---

	@Test
	void setMixedContentModeZeroFires() {
		// Real jadx output: the WebSettings.MIXED_CONTENT_ALWAYS_ALLOW constant compiles to 0.
		assertTrue(MIXED.matcher("settings.setMixedContentMode(0);").find(),
				"setMixedContentMode(0) — the real jadx-decompiled ALWAYS_ALLOW form — must fire");
	}

	@Test
	void setMixedContentModeZeroWithSpacesFires() {
		assertTrue(MIXED.matcher("settings.setMixedContentMode( 0 );").find(),
				"setMixedContentMode with surrounding whitespace must fire");
	}

	@Test
	void oldIdentifierFormStillDoesNotMatter() {
		// The constant value 0 is the decompiled reality; an identifier form (rare, e.g. a non-Android
		// shim that keeps the symbol) is not what jadx emits, but the literal-0 rule is what matters.
		assertFalse(MIXED.matcher("setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW);").find(),
				"the literal-0 rule does not match the identifier form (jadx never emits it anyway)");
	}

	@Test
	void neverAllowAndCompatModeDoNotFire() {
		// 1 == NEVER_ALLOW, 2 == COMPATIBILITY_MODE — only 0 (ALWAYS_ALLOW) is the vuln.
		assertFalse(MIXED.matcher("settings.setMixedContentMode(1);").find(),
				"NEVER_ALLOW (1) must NOT fire");
		assertFalse(MIXED.matcher("settings.setMixedContentMode(2);").find(),
				"COMPATIBILITY_MODE (2) must NOT fire");
	}

	@Test
	void unrelatedZeroArgDoesNotFire() {
		// The pattern is anchored on setMixedContentMode(, not a loose (0).
		assertFalse(MIXED.matcher("setJavaScriptEnabled(true); setSomething(0);").find(),
				"a different setter with a 0 arg must NOT fire the mixed-content rule");
	}

	// --- js_loadurl: loadUrl("javascript:...") ---

	@Test
	void loadUrlJavascriptSchemeFires() {
		assertTrue(JS_URL.matcher("webView.loadUrl(\"javascript:alert(1)\");").find(),
				"loadUrl(\"javascript:...\") must fire the js_loadurl rule");
	}

	@Test
	void loadUrlJavascriptWithSpacesFires() {
		assertTrue(JS_URL.matcher("wv.loadUrl( \"javascript:doSomething()\" );").find(),
				"loadUrl with whitespace before the javascript: literal must fire");
	}

	@Test
	void loadUrlHttpDoesNotFireJsRule() {
		// The http:// form is the cleartext_load rule's job, not js_loadurl.
		assertFalse(JS_URL.matcher("webView.loadUrl(\"http://example.com\");").find(),
				"an http:// loadUrl must NOT fire the javascript: rule");
	}

	@Test
	void loadUrlHttpsDoesNotFireJsRule() {
		assertFalse(JS_URL.matcher("webView.loadUrl(\"https://example.com\");").find(),
				"an https:// loadUrl must NOT fire the javascript: rule");
	}

	@Test
	void loadDataDoesNotFireJsRule() {
		// loadData is a different API; only loadUrl("javascript:") is the injection surface here.
		assertFalse(JS_URL.matcher("webView.loadData(\"javascript:...\", \"text/html\", \"UTF-8\");").find(),
				"loadData with a javascript: string arg must NOT fire the loadUrl-based js rule");
	}
}
