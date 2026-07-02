package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the cross-line {@link BroadcastScanCommand#BROADCAST_SENSITIVE_SPLIT} fix.
 *
 * <p>jadx decompiles the canonical build-then-send idiom across three statements on different
 * physical lines:
 * <pre>
 *   Intent intent = new Intent("com.app.C");
 *   intent.putExtra("password", str);   // line 2: putExtra + credential, NO sendBroadcast
 *   sendBroadcast(intent);              // line 3: sendBroadcast + intent-local, NO credential
 * </pre>
 * Every per-line arm of {@link BroadcastScanCommand#BROADCAST_SENSITIVE} welds
 * {@code putExtra} and {@code sendBroadcast} (or the credential name and {@code sendBroadcast})
 * with {@code .*} on ONE line, so none matches line 2 or line 3 — a silent high-severity FN
 * (credential broadcast). {@code BROADCAST_SENSITIVE_SPLIT} (DOTALL) matches the
 * credential-NAME-in-{@code putExtra("...")} followed across lines by {@code sendBroadcast(}.
 * Verified against real javac&#8594;d8&#8594;jadx output.
 */
class BroadcastSensitiveSplitTest {

	private static final Pattern SPLIT = BroadcastScanCommand.BROADCAST_SENSITIVE_SPLIT;

	@Test
	void crossLinePutExtraThenSendFires() {
		// The real jadx form: build Intent, putExtra password, sendBroadcast — three statements.
		String code = "Intent intent = new Intent(\"com.app.C\");\n"
				+ "intent.putExtra(\"password\", str);\n"
				+ "sendBroadcast(intent);";
		assertTrue(SPLIT.matcher(code).find(),
				"a credential put into an Intent extra then sent via sendBroadcast on a separate statement must fire (was a silent high FN)");
	}

	@Test
	void crossLineTokenExtraFires() {
		String code = "Intent i = new Intent(\"x\");\n"
				+ "i.putExtra(\"accessToken\", tok);\n"
				+ "sendBroadcast(i);";
		assertTrue(SPLIT.matcher(code).find(),
				"an accessToken extra sent on another line must fire");
	}

	@Test
	void forwardOrderPutExtraThenSendFires() {
		// The DOTALL pattern matches putExtra("cred"...) ... sendBroadcast in source order.
		String code = "i.putExtra(\"refreshToken\", rt);\n" + "sendBroadcast(i);";
		assertTrue(SPLIT.matcher(code).find(),
				"putExtra then sendBroadcast (forward order, two lines) must fire");
	}

	@Test
	void sameLineIsCaughtByPerLineArmsNotSplit() {
		// The split pattern matches the FORWARD cross-line form (putExtra then sendBroadcast across
		// lines). The same-line form `sendBroadcast(i.putExtra("password", pwd))` has sendBroadcast
		// BEFORE putExtra, so the split pattern does NOT match it — but that's fine: execute()'s
		// per-line BROADCAST_SENSITIVE arms catch the same-line form, and reportedKinds dedups so
		// the split fallback only runs when the per-line pass found nothing. This test documents the
		// split pattern's directional scope (forward only), not a requirement.
		assertFalse(SPLIT.matcher("sendBroadcast(i.putExtra(\"password\", pwd));").find(),
				"the split pattern is forward-only (putExtra→sendBroadcast); the same-line reverse-order form is handled by the per-line arms");
	}

	@Test
	void nonCredentialExtraDoesNotFire() {
		// A non-credential extra name (e.g. "pref_key") must not fire — same FP guard as the per-line form.
		String code = "Intent i = new Intent();\n"
				+ "i.putExtra(\"pref_key\", val);\n"
				+ "sendBroadcast(i);";
		assertFalse(SPLIT.matcher(code).find(),
				"a non-credential extra name broadcast must not fire (FP guard retained)");
	}

	@Test
	void putExtraWithoutSendBroadcastDoesNotFire() {
		// putExtra of a credential with NO sendBroadcast anywhere in the class is not a broadcast leak.
		String code = "Intent i = new Intent();\n" + "i.putExtra(\"password\", pwd);\n" + "i.setClass(this, Other.class);";
		assertFalse(SPLIT.matcher(code).find(),
				"a credential putExtra with no sendBroadcast must not fire");
	}

	@Test
	void sendBroadcastWithoutCredentialExtraDoesNotFire() {
		// sendBroadcast of an Intent with no credential extra is not a credential leak.
		String code = "Intent i = new Intent();\n" + "i.putExtra(\"message\", msg);\n" + "sendBroadcast(i);";
		assertFalse(SPLIT.matcher(code).find(),
				"a sendBroadcast with no credential extra must not fire");
	}
}
