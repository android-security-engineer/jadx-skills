package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the jadx-cast-form and no-suffix-numeric-seed arms added to
 * {@link HardcodedCryptoScanCommand}.
 *
 * <p>Two decompiler-specific shapes were silently missed:
 * <ul>
 *   <li>{@code HARDCODED_KEY_BYTES} matched {@code byte[]{0x12, ...}} but not the jadx cast form
 *       {@code byte[]{(byte)0x12, (byte)0x34}} — jadx emits an explicit {@code (byte)} cast on
 *       byte literals because Java byte literals overflow signed-byte range, so this is the most
 *       common decompiled key-array shape.</li>
 *   <li>{@code HARDCODED_SEED} matched {@code setSeed(123L)} but not the no-suffix
 *       {@code setSeed(123)} form jadx frequently emits.</li>
 * </ul>
 */
class HardcodedCryptoJadxFormTest {

	private static final Pattern KEY_BYTES = Pattern.compile(HardcodedCryptoScanCommand.HARDCODED_KEY_BYTES.pattern());
	private static final Pattern SEED = Pattern.compile(HardcodedCryptoScanCommand.HARDCODED_SEED.pattern());

	@Test
	void bareHexByteArrayStillFires() {
		assertTrue(KEY_BYTES.matcher("byte[] key = new byte[]{0x12, 0x34, 0x56, 0x78};").find(),
				"the bare 0x hex-literal form must still fire (regression guard)");
	}

	@Test
	void jadxCastByteArrayFires() {
		assertTrue(KEY_BYTES.matcher("byte[] key = new byte[]{(byte)0x12, (byte)0x34, (byte)0x56};").find(),
				"the jadx (byte)0x cast form is the most common decompiled key-array shape — must fire");
	}

	@Test
	void jadxCastWithSpaceFires() {
		assertTrue(KEY_BYTES.matcher("new byte[] { (byte) 0x9a, (byte) 0xbc };").find(),
				"the cast form with internal spaces must fire");
	}

	@Test
	void base64SecretKeySpecFires() {
		// The base64 arm matches a >=20-char base64 literal followed (later on the line) by SecretKeySpec,
		// i.e. the assign-then-build form: String k = "QUJDREVGR0hJSktMTU5PUA=="; SecretKeySpec(...).
		assertTrue(KEY_BYTES.matcher("String k = \"QUJDREVGR0hJSktMTU5PUA==\"; new SecretKeySpec(k.getBytes(), \"AES\");").find(),
				"a base64 key literal assigned then fed to SecretKeySpec must fire (regression guard)");
	}

	@Test
	void nonHexByteArrayDoesNotFire() {
		assertFalse(KEY_BYTES.matcher("byte[] data = new byte[]{1, 2, 3, 4};").find(),
				"decimal byte literals are not the hex key-array signature — must not fire (avoid noise)");
	}

	@Test
	void setSeedNoSuffixNumericFires() {
		assertTrue(SEED.matcher("secureRandom.setSeed(123);").find(),
				"setSeed(123) without the L suffix is a deterministic seed — must fire");
	}

	@Test
	void setSeedWithLFires() {
		assertTrue(SEED.matcher("secureRandom.setSeed(123L);").find(),
				"setSeed(123L) must still fire (regression guard)");
	}

	@Test
	void setSeedStringFires() {
		assertTrue(SEED.matcher("secureRandom.setSeed(\"fixed\");").find(),
				"a string seed is deterministic — must fire (regression guard)");
	}

	@Test
	void setSeedVariableDoesNotFire() {
		assertFalse(SEED.matcher("secureRandom.setSeed(seedBytes);").find(),
				"a variable-backed seed is not a hardcoded literal — must not fire (the [0-9]+ arm requires a digit)");
		assertFalse(SEED.matcher("secureRandom.setSeed(systemSeed.length);").find(),
				"a variable-property seed must not fire");
	}
}
