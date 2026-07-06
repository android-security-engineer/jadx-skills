package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code unvalidated_call} detection added to {@link ContentProviderScanCommand} for the
 * ContentProvider {@code call(String, String, Bundle)} free-form RPC entry point (CWE-862).
 *
 * <p>{@code call()} is NOT tied to the URI/selection permission model the CRUD methods use — an
 * exported provider's {@code call()} is an arbitrary method-dispatch channel a caller reaches with
 * {@code resolver.call(uri, "method", ...)}. The scanner previously covered only query/insert/update/
 * delete, so a provider that exposed privileged operations ONLY via {@code call()} (no CRUD override)
 * passed every check. The signature anchor tolerates jadx's {@code final}/{@code synchronized} echo
 * (between {@code public} and {@code Bundle}) and inlined param annotations ({@code @NonNull String}).
 */
class ContentProviderCallMethodTest {

	private static final Pattern CALL = ContentProviderScanCommand.CALL_METHOD;

	private static boolean calls(String line) {
		return CALL.matcher(line).find();
	}

	@Test
	void plainCallSignatureMatches() {
		assertTrue(calls("public Bundle call(String method, String arg, Bundle extras) {"),
				"plain public Bundle call(String must match");
	}

	@Test
	void finalCallSignatureMatches() {
		assertTrue(calls("public final Bundle call(String method, String arg, Bundle extras) {"),
				"public final Bundle call (jadx echoes final) must match");
	}

	@Test
	void synchronizedCallSignatureMatches() {
		assertTrue(calls("public synchronized Bundle call(String method, String arg, Bundle extras) {"),
				"public synchronized Bundle call (jadx echoes synchronized) must match");
	}

	@Test
	void parameterAnnotationCallMatches() {
		assertTrue(calls("public Bundle call(@NonNull String method, @Nullable String arg, Bundle extras) {"),
				"a call() signature with inlined @NonNull/@Nullable param annotations must match");
	}

	@Test
	void finalPlusParamAnnotationMatches() {
		assertTrue(calls("public final Bundle call(@NonNull String method, String arg, Bundle extras) {"),
				"final + param-annotation combo must match");
	}

	@Test
	void nonCallBundleMethodDoesNotMatch() {
		assertFalse(calls("public Bundle getResult() {"),
				"a non-call Bundle return method must not match the call() signature");
		assertFalse(calls("public Bundle callBack() {"),
				"a method named callBack (not call) must not match");
	}
}
