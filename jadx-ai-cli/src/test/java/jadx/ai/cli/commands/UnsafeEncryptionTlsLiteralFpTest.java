package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the false-positive fix in {@link UnsafeEncryptionScanCommand#INSECURE_TLS}.
 *
 * <p>{@code TLSv1\b} was a FALSE-POSITIVE AMPLIFIER: the {@code \b} word boundary sits between the
 * {@code 1} and the {@code .}, so the modern secure protocol {@code "TLSv1.2"} matched the
 * insecure-TLS-1.0 arm — every app that pinned TLS 1.2 was flagged {@code insecure_tls_version}
 * <b>high</b>. The negative-lookahead {@code (?![.\d])} matches bare TLS 1.0 only, not TLS 1.1/1.2.
 * Verified against real javac&#8594;d8&#8594;jadx output ({@code SSLContext.getInstance("TLSv1.2")}
 * decompiles with the literal preserved).
 */
class UnsafeEncryptionTlsLiteralFpTest {

	private static final java.util.regex.Pattern INSECURE_TLS = UnsafeEncryptionScanCommand.INSECURE_TLS;

	// --- the real jadx-decompiled forms ---

	@Test
	void tls12SafeDoesNotFire() {
		assertFalse(INSECURE_TLS.matcher("return SSLContext.getInstance(\"TLSv1.2\");").find(),
				"\"TLSv1.2\" (modern secure protocol) must NOT fire the insecure-TLS rule (was a high FP)");
	}

	@Test
	void tls11StillFires() {
		assertTrue(INSECURE_TLS.matcher("return SSLContext.getInstance(\"TLSv1.1\");").find(),
				"\"TLSv1.1\" (deprecated) must still fire");
	}

	@Test
	void tls10StillFires() {
		assertTrue(INSECURE_TLS.matcher("return SSLContext.getInstance(\"TLSv1\");").find(),
				"\"TLSv1\" (TLS 1.0, insecure) must still fire");
	}

	@Test
	void sslv3StillFires() {
		assertTrue(INSECURE_TLS.matcher("return SSLContext.getInstance(\"SSLv3\");").find(),
				"\"SSLv3\" must still fire");
	}

	// --- the PROTOCOL_TLSV1 form had the same .-boundary bug ---

	@Test
	void protocolTlsv12SafeDoesNotFire() {
		assertFalse(INSECURE_TLS.matcher("ctx.init(k, null, null); /* PROTOCOL_TLSV12 */").find(),
				"a PROTOCOL_TLSV12 reference must NOT fire (the .-boundary bug also hit the PROTOCOL arm)");
	}

	@Test
	void protocolTlsv1StillFires() {
		assertTrue(INSECURE_TLS.matcher("String p = PROTOCOL_TLSV1;").find(),
				"a bare PROTOCOL_TLSV1 reference must still fire");
	}
}
