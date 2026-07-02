package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the false-positive fix in {@link BroadcastScanCommand#BROADCAST_SENSITIVE}.
 *
 * <p>The old rule paired {@code sendBroadcast.*} with the bare substring {@code key} (also
 * {@code auth}/{@code session}), so {@code sendBroadcast(...putExtra("pref_key", v))} — broadcasting
 * a normal preference/map key — was flagged {@code broadcast_sensitive_data} <b>high</b>. Now the
 * credential token must appear inside a {@code putExtra("...")} extra-NAME literal. Verified
 * against real javac&#8594;d8&#8594;jadx output.
 */
class BroadcastSensitiveFpTest {

	private static final java.util.regex.Pattern BROADCAST_SENSITIVE = BroadcastScanCommand.BROADCAST_SENSITIVE;

	@Test
	void prefKeyCompactDoesNotFire() {
		assertFalse(BROADCAST_SENSITIVE.matcher(
				"sendBroadcast(new Intent(\"X\").putExtra(\"pref_key\", v));").find(),
				"broadcasting a pref_key extra is NOT a credential leak — must NOT fire (was a high FP)");
	}

	@Test
	void prefKeySplitSameLineDoesNotFire() {
		assertFalse(BROADCAST_SENSITIVE.matcher(
				"i.putExtra(\"pref_key\", v); ctx.sendBroadcast(i);").find(),
				"split pref_key + sendBroadcast on one line must NOT fire");
	}

	@Test
	void mapKeyDoesNotFire() {
		assertFalse(BROADCAST_SENSITIVE.matcher(
				"sendBroadcast(intent.putExtra(\"map_key\", k));").find(),
				"a map_key extra must NOT fire");
	}

	@Test
	void passwordCompactStillFires() {
		assertTrue(BROADCAST_SENSITIVE.matcher(
				"sendBroadcast(new Intent(\"X\").putExtra(\"password\", pwd));").find(),
				"broadcasting a password extra must still fire");
	}

	@Test
	void passwordSplitStillFires() {
		assertTrue(BROADCAST_SENSITIVE.matcher(
				"i.putExtra(\"password\", pwd); ctx.sendBroadcast(i);").find(),
				"split password + sendBroadcast on one line must still fire");
	}

	@Test
	void apiKeyStillFires() {
		assertTrue(BROADCAST_SENSITIVE.matcher(
				"i.putExtra(\"apiKey\", k); ctx.sendBroadcast(i);").find(),
				"broadcasting an apiKey extra must still fire");
	}

	@Test
	void accessTokenStillFires() {
		assertTrue(BROADCAST_SENSITIVE.matcher(
				"i.putExtra(\"accessToken\", tok); ctx.sendBroadcast(i);").find(),
				"broadcasting an accessToken extra must still fire");
	}
}
