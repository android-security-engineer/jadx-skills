package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the StringBuilder-fold and field-indirect deepening of
 * {@link HardcodedCryptoScanCommand#HARDCODED_SYMMETRIC_KEY},
 * {@link HardcodedCryptoScanCommand#HARDCODED_IV}, and {@link HardcodedCryptoScanCommand#HARDCODED_NONCE}.
 *
 * <p>Two real-world forms jadx emits that the old inline arms MISSED (high-severity FN):
 * <ol>
 *   <li><b>StringBuilder fold</b> — a key/IV/nonce assembled via {@code sb.append("part1").append("part2")}
 *       (a common obfuscation idiom) is constant-folded by javac/d8, and jadx emits it with an EXTRA
 *       paren around the folded literal: {@code SecretKeySpec(("MySuperSecretKey123456").getBytes(), "AES")},
 *       {@code IvParameterSpec(("0102030405060708").getBytes())},
 *       {@code GCMParameterSpec(128, ("01020304050607").getBytes())}. The old inline arms required the
 *       literal immediately after {@code \s*}; the extra {@code (} defeated them. Fix: {@code \(?}.</li>
 *   <li><b>Field-indirect</b> — a {@code static final String KEY = "..."} field whose value flows to
 *       {@code new SecretKeySpec(KEY.getBytes(), "AES")} on another line. jadx does NOT inline a
 *       {@code static final String} field into its use sites (unlike {@code static final int}), so the
 *       declaration survives and the sink line has no literal. Fix: a name-gated String-field-declaration
 *       arm (exact key-ish token, not a substring — to avoid the KEYWORDS/keyDesc FP).
 *   </li>
 * </ol>
 * Both verified against real javac&#8594;d8&#8594;jadx output.
 */
class HardcodedCryptoObfuscationFoldTest {

	private static final java.util.regex.Pattern SYM = HardcodedCryptoScanCommand.HARDCODED_SYMMETRIC_KEY;
	private static final java.util.regex.Pattern IV = HardcodedCryptoScanCommand.HARDCODED_IV;
	private static final java.util.regex.Pattern NONCE = HardcodedCryptoScanCommand.HARDCODED_NONCE;

	// --- StringBuilder fold: the obfuscated form must now fire ---

	@Test
	void stringBuilderFoldedKeyFires() {
		assertTrue(SYM.matcher(
				"new SecretKeySpec((\"MySuperSecretKey123456\").getBytes(), \"AES\");").find(),
				"a StringBuilder-assembled key folded to the extra-paren form must fire (was a high FN)");
	}

	@Test
	void stringBuilderFoldedIvFires() {
		assertTrue(IV.matcher(
				"new IvParameterSpec((\"0102030405060708\").getBytes());").find(),
				"a StringBuilder-assembled IV folded to the extra-paren form must fire");
	}

	@Test
	void stringBuilderFoldedGcmNonceFires() {
		assertTrue(NONCE.matcher(
				"new GCMParameterSpec(128, (\"01020304050607\").getBytes());").find(),
				"a StringBuilder-assembled GCM nonce folded to the extra-paren form must fire");
	}

	// --- the direct (non-obfuscated) form still fires ---

	@Test
	void directKeyStillFires() {
		assertTrue(SYM.matcher("new SecretKeySpec(\"MySuperSecretKey123456\".getBytes(), \"AES\");").find(),
				"the direct inline key form must still fire");
	}

	@Test
	void directIvStillFires() {
		assertTrue(IV.matcher("new IvParameterSpec(\"0102030405060708\".getBytes());").find(),
				"the direct inline IV form must still fire");
	}

	@Test
	void directGcmNonceStillFires() {
		assertTrue(NONCE.matcher("new GCMParameterSpec(128, \"01020304050607\".getBytes());").find(),
				"the direct inline GCM nonce form must still fire");
	}

	// --- field-indirect: static final String KEY field must fire on the declaration line ---

	@Test
	void staticFinalKeyFieldFires() {
		assertTrue(SYM.matcher("    static final String KEY = \"SuperSecretKey123\";").find(),
				"a `static final String KEY = \"...\"` field (value flows to SecretKeySpec elsewhere) must fire");
	}

	@Test
	void staticFinalSecretKeyFieldFires() {
		assertTrue(SYM.matcher("    static final String SECRET_KEY = \"abcdef0123456789\";").find(),
				"a SECRET_KEY String field must fire");
	}

	@Test
	void apiKeyFieldFires() {
		assertTrue(SYM.matcher("    String apiKey = \"abcdef0123456789\";").find(),
				"an apiKey String field must fire");
	}

	// --- FP guards: non-key String fields must NOT fire ---

	@Test
	void keywordsFieldDoesNotFire() {
		assertFalse(SYM.matcher("    static final String KEYWORDS = \"search,terms,here\";").find(),
				"a KEYWORDS field (substring of KEY) must NOT fire — exact-token gate");
	}

	@Test
	void keyDescFieldDoesNotFire() {
		assertFalse(SYM.matcher("    String keyDesc = \"the key is long\";").find(),
				"a keyDesc field must NOT fire — exact-token gate");
	}

	@Test
	void keyboardFieldDoesNotFire() {
		assertFalse(SYM.matcher("    static final String KEYBOARD = \"qwertyuiop\";").find(),
				"a KEYBOARD field must NOT fire — exact-token gate");
	}
}
