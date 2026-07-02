package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the false-positive fix in {@link InsecureFileIoScanCommand#SENSITIVE_UNENCRYPTED}.
 *
 * <p>The old rule paired {@code FileOutputStream.*} with the bare substring {@code key} (also
 * {@code auth}/{@code session}), so {@code new FileOutputStream("pref_key_cache.bin")} — a normal
 * preferences-cache file — was flagged {@code sensitive_file_unencrypted} <b>high</b>. The generic
 * substrings are removed; only concrete credential tokens remain. Verified against real
 * javac&#8594;d8&#8594;jadx output.
 */
class InsecureFileIoSensitiveUnencryptedFpTest {

	private static final java.util.regex.Pattern SENSITIVE_UNENCRYPTED =
			InsecureFileIoScanCommand.SENSITIVE_UNENCRYPTED;

	@Test
	void prefKeyCacheDoesNotFire() {
		assertFalse(SENSITIVE_UNENCRYPTED.matcher(
				"FileOutputStream fileOutputStream = new FileOutputStream(\"pref_key_cache.bin\");").find(),
				"a preferences-key cache file is NOT a credential — must NOT fire (was a high FP)");
	}

	@Test
	void authorLogDoesNotFire() {
		assertFalse(SENSITIVE_UNENCRYPTED.matcher(
				"FileOutputStream fos = new FileOutputStream(\"author_bio.txt\");").find(),
				"\"author\" must NOT fire via the removed `auth` substring");
	}

	@Test
	void sessionIdFileDoesNotFire() {
		assertFalse(SENSITIVE_UNENCRYPTED.matcher(
				"FileOutputStream fos = new FileOutputStream(\"session_id.dat\");").find(),
				"\"session_id\" must NOT fire via the removed `session` substring (sessionId is not a credential)");
	}

	@Test
	void passwordFileStillFires() {
		assertTrue(SENSITIVE_UNENCRYPTED.matcher(
				"FileOutputStream fos = new FileOutputStream(\"password.dat\");").find(),
				"a password file must still fire");
	}

	@Test
	void apiKeyFileStillFires() {
		assertTrue(SENSITIVE_UNENCRYPTED.matcher(
				"FileOutputStream fos = new FileOutputStream(\"apiKey.bin\");").find(),
				"an apiKey file must still fire");
	}

	@Test
	void openFileOutputSecretStillFires() {
		assertTrue(SENSITIVE_UNENCRYPTED.matcher(
				"openFileOutput(\"secret_store\", 0);").find(),
				"openFileOutput with a secret name must still fire");
	}
}
