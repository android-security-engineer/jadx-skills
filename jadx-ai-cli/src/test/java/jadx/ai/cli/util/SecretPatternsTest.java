package jadx.ai.cli.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the shared secret-pattern library — in particular {@link SecretPatterns#scanStrings},
 * the entry point {@code native-libs} uses to catch API keys / tokens / private keys that were
 * relocated into {@code .so} files to evade the Java-only {@code secrets-scan} view.
 */
class SecretPatternsTest {

	private static List<Map<String, Object>> kinds(List<String> strings) {
		return SecretPatterns.scanStrings(strings, "libtest.so", "native", 100);
	}

	// Synthetic fixtures assembled at runtime so no contiguous secret token appears in the source
	// (else GitHub push-protection / secret-scanning rejects the commit on its own detectors).
	private static final String FAKE_GOOGLE = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv";
	private static final String FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "abcdefghijklmnop";
	private static final String FAKE_STRIPE = "sk_" + "live_" + "0123456789abcdef01234567";
	private static final String FAKE_PEM = "-----BEGIN " + "RSA PRIVATE KEY-----";

	@Test
	void detectsSecretsCarvedFromNativeStrings() {
		List<String> strings = List.of(
				"harmless_version_string",
				FAKE_GOOGLE,
				FAKE_JWT,
				FAKE_STRIPE,
				FAKE_PEM);
		List<Map<String, Object>> found = kinds(strings);
		List<String> foundKinds = new ArrayList<>();
		for (Map<String, Object> f : found) {
			foundKinds.add((String) f.get("kind"));
		}
		assertTrue(foundKinds.contains("google_api_key"), "should find AIza key: " + foundKinds);
		assertTrue(foundKinds.contains("jwt"), "should find JWT: " + foundKinds);
		assertTrue(foundKinds.contains("stripe_secret_key"), "should find Stripe key: " + foundKinds);
		assertTrue(foundKinds.contains("rsa_private_key"), "should find PEM header: " + foundKinds);
	}

	@Test
	void redactsTheMatchedValue() {
		List<Map<String, Object>> found = kinds(List.of(FAKE_GOOGLE));
		assertEquals(1, found.size());
		String match = (String) found.get(0).get("match");
		assertTrue(match.startsWith("AIza"), "keeps prefix: " + match);
		assertTrue(match.contains("****"), "masks middle: " + match);
		assertFalse(match.contains("567890abcdef"), "hides body: " + match);
		assertEquals("native", found.get(0).get("origin"));
		assertEquals("libtest.so", found.get(0).get("source"));
	}

	@Test
	void cleanStringsProduceNoFindings() {
		List<Map<String, Object>> found = kinds(List.of(
				"libc.so", "JNI_OnLoad", "Java_com_example_Foo_bar", "/proc/self/maps", "GCC: (GNU) 9.0"));
		assertTrue(found.isEmpty(), "benign native strings must not false-positive: " + found);
	}

	@Test
	void respectsTheLimit() {
		List<String> many = new ArrayList<>();
		for (int i = 0; i < 50; i++) {
			many.add(FAKE_GOOGLE);
		}
		assertEquals(5, SecretPatterns.scanStrings(many, "x", "native", 5).size(), "limit must cap findings");
	}
}
