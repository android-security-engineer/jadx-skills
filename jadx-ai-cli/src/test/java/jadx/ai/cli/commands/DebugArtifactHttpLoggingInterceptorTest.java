package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the OkHttp {@code HttpLoggingInterceptor} debug-lib detection in
 * {@link DebugArtifactScanCommand}.
 *
 * <p>{@code HttpLoggingInterceptor} at {@code Level.BODY}/{@code Level.HEADERS} writes the full HTTP
 * request/response payload — Authorization headers, tokens, PII — to Logcat. It is as much a
 * release-build data-leak surface as Chucker/Chuck (the in-app HTTP inspectors already listed), but
 * the debug-lib list missed it. Now a {@code debug_lib} entry; the {@code DEBUG_MARKER} gate also
 * lists it so a class referencing only HttpLoggingInterceptor is scanned.
 */
class DebugArtifactHttpLoggingInterceptorTest {

	private static final java.util.regex.Pattern LIB = DebugArtifactScanCommand.HTTP_LOGGING_INTERCEPTOR;
	private static final java.util.regex.Pattern GATE = java.util.regex.Pattern.compile(
			"Stetho|Flipper|LeakCanary|Chucker|Chuck|HttpInspector|BinderSpy|DebugDB|LynxDebugger|"
					+ "SegunFranko|HttpLoggingInterceptor|BuildConfig\\.DEBUG|Build\\.BETA|StrictMode|startMethodTracing");

	@Test
	void httpLoggingInterceptorDeclarationFires() {
		assertTrue(LIB.matcher("HttpLoggingInterceptor logging = new HttpLoggingInterceptor();").find(),
				"a HttpLoggingInterceptor declaration must fire the debug-lib rule");
	}

	@Test
	void setLevelBodyFires() {
		assertTrue(LIB.matcher("logging.setLevel(HttpLoggingInterceptor.Level.BODY);").find(),
				"the canonical setLevel(Level.BODY) setup must fire — the full-payload leak config");
	}

	@Test
	void setLevelHeadersFires() {
		assertTrue(LIB.matcher("interceptor.setLevel(HttpLoggingInterceptor.Level.HEADERS);").find(),
				"Level.HEADERS (logs Authorization/Cookie headers) must fire");
	}

	@Test
	void gateAdmitsHttpLoggingInterceptorClass() {
		// A class that references ONLY HttpLoggingInterceptor (no Stetho/Flipper/etc.) must still pass
		// the DEBUG_MARKER gate, or the whole class is skipped and the lib is never reported.
		assertTrue(GATE.matcher("HttpLoggingInterceptor logging = new HttpLoggingInterceptor();").find(),
				"the gate must admit a class whose only debug artifact is HttpLoggingInterceptor");
	}

	@Test
	void nonOkHttpLoggerDoesNotFire() {
		assertFalse(LIB.matcher("Logger log = Logger.getLogger(\"x\");").find(),
				"a generic java.util.logging Logger must NOT fire the HttpLoggingInterceptor rule");
		assertFalse(LIB.matcher("Log.d(TAG, \"done\");").find(),
				"android.util.Log must NOT fire the HttpLoggingInterceptor rule");
	}
}
