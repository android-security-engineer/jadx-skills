package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the d8-desugared lambda hostname-verifier detection in {@link SslScanCommand}.
 *
 * <p>{@code new OkHttpClient.Builder().hostnameVerifier((h, s) -> true)} is one of the most common
 * real-world TLS bypasses. d8 desugars the lambda into an anonymous {@code HostnameVerifier} whose
 * {@code verify()} body is a <b>synthetic bridge</b> call ({@code return X.lambda$m$N(...);}), and
 * the real {@code return true;} lives in the synthetic {@code lambda$m$N} method — whose name is
 * never {@code verify}. So {@link SslScanCommand#VERIFY_TRUE} matches neither the bridge nor the
 * synthetic method. The detector now pairs a class-scope {@code hostnameVerifier(} installer with
 * the synthetic {@link SslScanCommand#LAMBDA_TRUE} method.
 */
class SslLambdaHostnameVerifierTest {

	private static final Pattern LAMBDA_TRUE = SslScanCommand.LAMBDA_TRUE;
	private static final Pattern HV_CALL = SslScanCommand.HOSTNAME_VERIFIER_CALL;
	private static final Pattern TLS_MARKER = Pattern.compile(
			"HostnameVerifier|TrustManager|SSLContext|SSLSocketFactory|X509|javax\\.net\\.ssl|onReceivedSslError");

	/** Mirrors scanClass()'s lambda-bridge test: tlsClass ∧ hostnameVerifier( ∧ synthetic return-true. */
	private static boolean bypass(String code) {
		return TLS_MARKER.matcher(code).find()
				&& HV_CALL.matcher(code).find()
				&& LAMBDA_TRUE.matcher(code).find();
	}

	@Test
	void desugaredLambdaBridgeFires() {
		// The exact jadx/d8 shape: anonymous HostnameVerifier bridges to lambda$lambdaVerifier$0,
		// which holds the real `return true;`.
		String code = "class SSLTest {\n"
				+ "  void lambdaVerifier() {\n"
				+ "    new OkHttpClient.Builder().hostnameVerifier(new HostnameVerifier() {\n"
				+ "      @Override public boolean verify(String str, SSLSession sSLSession) {\n"
				+ "        return SSLTest.lambda$lambdaVerifier$0(str, sSLSession);\n"
				+ "      }\n"
				+ "    }).build();\n"
				+ "  }\n"
				+ "  static /* synthetic */ boolean lambda$lambdaVerifier$0(String str, SSLSession sSLSession) {\n"
				+ "    return true;\n"
				+ "  }\n"
				+ "}";
		assertTrue(bypass(code),
				"a desugared lambda hostname verifier returning true must fire — the common OkHttp bypass");
	}

	@Test
	void syntheticLambdaTrueAloneIsNotEnough() {
		// Without the hostnameVerifier( installer, a lambda returning true is just some function —
		// not necessarily a hostname bypass.
		String code = "class U {\n"
				+ "  static /* synthetic */ boolean lambda$isEnabled$0(String s) {\n"
				+ "    return true;\n"
				+ "  }\n"
				+ "}";
		assertFalse(bypass(code),
				"a synthetic lambda$m$N returning true with no hostnameVerifier installer must NOT fire");
	}

	@Test
	void hostnameVerifierWithoutLambdaTrueDoesNotFireLambdaRule() {
		// A hostnameVerifier installed with a real verifier (no synthetic return-true) — VERIFY_TRUE
		// or ALLOW_ALL handles other shapes; the lambda rule stays silent.
		String code = "class V {\n"
				+ "  builder.hostnameVerifier(new RealHostnameVerifier());\n"
				+ "}";
		assertFalse(bypass(code),
				"a hostnameVerifier call with no synthetic return-true lambda must NOT fire the lambda rule");
	}

	@Test
	void plainVerifyReturnTrueDoesNotMatchLambdaPattern() {
		// VERIFY_TRUE handles the plain verify(){return true;} form; LAMBDA_TRUE must not also match it
		// (avoids double-counting) — the lambda$m$N naming is the discriminator.
		assertFalse(LAMBDA_TRUE.matcher("public boolean verify(String h, SSLSession s) { return true; }").find(),
				"a plain verify() returning true must NOT match the synthetic lambda$m$N pattern");
	}

	@Test
	void lambdaReturningFalseDoesNotFire() {
		String code = "class W {\n"
				+ "  builder.hostnameVerifier(new HostnameVerifier() {\n"
				+ "    public boolean verify(String h, SSLSession s) { return W.lambda$m$0(h, s); }\n"
				+ "  });\n"
				+ "  static boolean lambda$m$0(String h, SSLSession s) { return false; }\n"
				+ "}";
		assertFalse(bypass(code),
				"a lambda returning false is a strict verifier — must NOT fire");
	}
}
