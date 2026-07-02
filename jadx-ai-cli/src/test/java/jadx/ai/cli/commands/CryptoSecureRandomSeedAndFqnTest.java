package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards two real-world false negatives in {@link CryptoScanCommand}, both verified against actual
 * javac&#8594;d8&#8594;jadx decompiled output (imports-on AND imports-off).
 *
 * <ul>
 *   <li><b>{@code static_secure_random_seed}</b> — {@code SecureRandom.setSeed(<literal>)} seeds the
 *       CSPRNG with a constant, making its output fully predictable. The class javadoc claimed coverage
 *       of insecure RNG, but the implementation only matched {@code new Random()}/{@code Math.random()}
 *       and had ZERO detection for a static {@code SecureRandom} seed. New
 *       {@link CryptoScanCommand#SR_STATIC_SEED} (gated by class-scope
 *       {@link CryptoScanCommand#SECURE_RANDOM_USAGE}) catches it; variable seeds do not fire.</li>
 *   <li><b>FQN robustness</b> — four {@code new\s+<ShortName>} patterns ({@code SecretKeySpec},
 *       {@code IvParameterSpec}, {@code GCMParameterSpec}, {@code Random}) failed when jadx emitted a
 *       fully-qualified prefix ({@code new javax.crypto.spec.SecretKeySpec(}, imports-off or an
 *       un-importable type). Each now carries an optional {@code (?:[\w.]*\.)?} prefix.</li>
 * </ul>
 */
class CryptoSecureRandomSeedAndFqnTest {

	private static final java.util.regex.Pattern SR_SEED = CryptoScanCommand.SR_STATIC_SEED;
	private static final java.util.regex.Pattern SR_USAGE = CryptoScanCommand.SECURE_RANDOM_USAGE;
	private static final java.util.regex.Pattern SECRET_KEY = CryptoScanCommand.SECRET_KEY;
	private static final java.util.regex.Pattern IV = CryptoScanCommand.IV_LITERAL;
	private static final java.util.regex.Pattern GCM_IV = CryptoScanCommand.GCM_IV_LITERAL;
	private static final java.util.regex.Pattern INSECURE_RNG = CryptoScanCommand.INSECURE_RANDOM;

	// --- static_secure_random_seed ---

	@Test
	void setSeedLongLiteralFires() {
		// Real jadx output: `secureRandom.setSeed(0L);`
		assertTrue(SR_SEED.matcher("secureRandom.setSeed(0L);").find(),
				"setSeed(0L) — the canonical static-seed form — must fire");
	}

	@Test
	void setSeedIntLiteralFires() {
		assertTrue(SR_SEED.matcher("sr.setSeed(12345);").find(),
				"an int-literal setSeed must fire");
	}

	@Test
	void setSeedNegativeLiteralFires() {
		assertTrue(SR_SEED.matcher("sr.setSeed(-1L);").find(),
				"a negative literal seed must fire");
	}

	@Test
	void setSeedByteArrayInitializerFires() {
		assertTrue(SR_SEED.matcher("secureRandom.setSeed(new byte[]{1, 2, 3, 4});").find(),
				"setSeed(new byte[]{...}) with a literal initializer must fire");
	}

	@Test
	void setSeedSizedByteArrayFires() {
		assertTrue(SR_SEED.matcher("secureRandom.setSeed(new byte[4]);").find(),
				"setSeed(new byte[4]) — a fixed all-zero seed — must fire");
	}

	@Test
	void setSeedChainedFires() {
		assertTrue(SR_SEED.matcher("new SecureRandom().setSeed(0L);").find(),
				"the chained new SecureRandom().setSeed(0L) form must fire");
	}

	@Test
	void setSeedFqnSecureRandomFires() {
		assertTrue(SR_SEED.matcher("new java.security.SecureRandom().setSeed(0L);").find(),
				"the fully-qualified SecureRandom chained form must fire");
	}

	@Test
	void setSeedVariableDoesNotFire() {
		assertFalse(SR_SEED.matcher("secureRandom.setSeed(someVar);").find(),
				"a variable seed must NOT fire (correct usage)");
	}

	@Test
	void setSeedCurrentTimeDoesNotFire() {
		assertFalse(SR_SEED.matcher("secureRandom.setSeed(System.currentTimeMillis());").find(),
				"setSeed(System.currentTimeMillis()) must NOT fire (time-based, not a constant)");
	}

	@Test
	void setSeedGenerateSeedDoesNotFire() {
		// setSeed(SecureRandom.getInstanceStrong().generateSeed(n)) is the CORRECT usage.
		assertFalse(SR_SEED.matcher("sr.setSeed(SecureRandom.getInstanceStrong().generateSeed(16));").find(),
				"setSeed(generateSeed(n)) — the correct re-seed — must NOT fire");
	}

	@Test
	void secureRandomUsageGateAdmitsClass() {
		// The class-scope gate must see a SecureRandom reference, or the per-line seed rule is skipped.
		assertTrue(SR_USAGE.matcher("SecureRandom sr = new SecureRandom();").find(),
				"a class using SecureRandom must pass the class-scope gate");
		assertTrue(SR_USAGE.matcher("java.security.SecureRandom sr = new SecureRandom();").find(),
				"the FQN form must also pass the gate");
	}

	// --- FQN robustness ---

	@Test
	void secretKeySpecShortAndFqnBothFire() {
		assertTrue(SECRET_KEY.matcher("new SecretKeySpec(key, \"AES\");").find(),
				"short-name SecretKeySpec must fire (imports-on)");
		assertTrue(SECRET_KEY.matcher("new javax.crypto.spec.SecretKeySpec(key, \"AES\");").find(),
				"fully-qualified SecretKeySpec must fire (imports-off)");
	}

	@Test
	void ivLiteralShortAndFqnBothFire() {
		assertTrue(IV.matcher("new IvParameterSpec(new byte[16]);").find(),
				"short-name IvParameterSpec must fire");
		assertTrue(IV.matcher("new javax.crypto.spec.IvParameterSpec(new byte[16]);").find(),
				"fully-qualified IvParameterSpec must fire");
	}

	@Test
	void gcmIvShortAndFqnBothFire() {
		assertTrue(GCM_IV.matcher("new GCMParameterSpec(128, new byte[12]);").find(),
				"short-name GCMParameterSpec must fire");
		assertTrue(GCM_IV.matcher("new javax.crypto.spec.GCMParameterSpec(128, new byte[12]);").find(),
				"fully-qualified GCMParameterSpec must fire");
	}

	@Test
	void insecureRandomShortAndFqnBothFire() {
		assertTrue(INSECURE_RNG.matcher("new Random();").find(),
				"short-name new Random() must fire");
		assertTrue(INSECURE_RNG.matcher("new java.util.Random();").find(),
				"fully-qualified new java.util.Random() must fire");
		assertTrue(INSECURE_RNG.matcher("double x = Math.random();").find(),
				"Math.random() must fire");
	}

	@Test
	void fqnPrefixDoesNotOverMatchRandomizer() {
		// The Random arm requires `(` immediately after `Random`, so Randomizer/etc. don't fire.
		assertFalse(INSECURE_RNG.matcher("new Randomizer();").find(),
				"a Randomizer class must NOT fire the Random() rule");
	}
}
