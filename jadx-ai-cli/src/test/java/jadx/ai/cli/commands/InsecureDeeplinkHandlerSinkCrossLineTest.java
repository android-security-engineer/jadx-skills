package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the cross-line {@code deeplink_sql_injection}/{@code deeplink_webview_load}/
 * {@code deeplink_class_loading} fix in {@link InsecureDeeplinkHandlerScanCommand}.
 *
 * <p>These three rules used a same-line {@code source.*sink} AND ({@code getData.*loadUrl},
 * {@code getQueryParameter.*rawQuery}, {@code getData.*Class.forName}). jadx decompiles a real
 * handler with the URI source on one line ({@code Uri u = getIntent().getData()}) and the sink on
 * another ({@code webView.loadUrl(u.toString())}) — so all three high findings were systematically
 * missed. Fixed with the deeplink/exported-provider pattern: class-scoped {@code DEEPLINK_SOURCE} ∧
 * per-line {@code SQL_SINK}/{@code WEBVIEW_SINK}/{@code CLASS_LOAD_SINK} via
 * {@link InsecureDeeplinkHandlerScanCommand#deeplinkSinkSignal}.
 */
class InsecureDeeplinkHandlerSinkCrossLineTest {

	private static boolean classHasSource(String code) {
		return InsecureDeeplinkHandlerScanCommand.DEEPLINK_SOURCE.matcher(code).find();
	}

	@Test
	void crossLineWebviewLoadFires() {
		String code = "Uri url = getIntent().getData();\n"
				+ "String s = url.toString();\n"
				+ "webView.loadUrl(s);";
		assertTrue(InsecureDeeplinkHandlerScanCommand.deeplinkSinkSignal(classHasSource(code), "webView.loadUrl(s);"),
				"a deep-link URI read on one line and loaded in WebView on another must fire");
	}

	@Test
	void sameLineWebviewLoadStillFires() {
		String code = "webView.loadUrl(getIntent().getData().toString());";
		assertTrue(InsecureDeeplinkHandlerScanCommand.deeplinkSinkSignal(classHasSource(code), code),
				"the inlined same-line webview form must still fire");
	}

	@Test
	void crossLineSqlInjectionFires() {
		String code = "String q = uri.getQueryParameter(\"q\");\n"
				+ "Cursor c = db.rawQuery(q, null);";
		assertTrue(InsecureDeeplinkHandlerScanCommand.deeplinkSinkSignal(classHasSource(code), "Cursor c = db.rawQuery(q, null);"),
				"a deep-link query param on one line fed to rawQuery on another must fire");
	}

	@Test
	void crossLineClassLoadingFires() {
		String code = "String cls = uri.getQueryParameter(\"class\");\n"
				+ "Object o = Class.forName(cls);";
		assertTrue(InsecureDeeplinkHandlerScanCommand.deeplinkSinkSignal(classHasSource(code), "Object o = Class.forName(cls);"),
				"a deep-link param on one line fed to Class.forName on another must fire");
	}

	@Test
	void fragmentInstantiateFires() {
		String code = "Uri data = getIntent().getData();\n"
				+ "Fragment f = Fragment.instantiate(this, data.getLastPathSegment());";
		assertTrue(InsecureDeeplinkHandlerScanCommand.deeplinkSinkSignal(classHasSource(code),
						"Fragment f = Fragment.instantiate(this, data.getLastPathSegment());"),
				"Fragment.instantiate fed by a deep-link must fire");
	}

	@Test
	void noDeepLinkSourceDoesNotFire() {
		// A WebView load with no deep-link source in the class is not a deep-link webview load.
		String code = "webView.loadUrl(\"https://example.com\");";
		assertFalse(InsecureDeeplinkHandlerScanCommand.deeplinkSinkSignal(classHasSource(code), code),
				"without a deep-link source, a static WebView URL is not deeplink_webview_load");
	}

	@Test
	void sourceWithoutSinkDoesNotFire() {
		String code = "Uri data = getIntent().getData();\n"
				+ "String host = data.getHost();";
		assertFalse(InsecureDeeplinkHandlerScanCommand.deeplinkSinkSignal(classHasSource(code), "String host = data.getHost();"),
				"a deep-link source without a sql/webview/class sink must not fire");
	}
}
