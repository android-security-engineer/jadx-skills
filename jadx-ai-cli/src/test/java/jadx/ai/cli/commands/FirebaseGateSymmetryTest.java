package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code FIREBASE_MARKER} gate / RULES-set symmetry in {@link FirebaseScanCommand}.
 *
 * <p>execute() skips any class/resource whose text does not match {@code FIREBASE_MARKER}, so every
 * rule's anchor must also appear in the gate. The gate was out of sync: the {@code firebase_app_id}
 * rule matches the mobilesdk app id {@code 1:NN:android:HH}, a bare string constant that can appear
 * with NO {@code Firebase}/{@code AIza}/{@code firebaseio} reference (e.g. a build-config or
 * analytics helper holding only the project id). A pure app-id class was skipped and
 * {@code firebase_app_id} never fired.
 */
class FirebaseGateSymmetryTest {

	private static boolean gated(String code) {
		return FirebaseScanCommand.FIREBASE_MARKER.matcher(code).find();
	}

	@Test
	void mobileAppIdClassPassesGate() {
		assertTrue(gated("String appId = \"1:123456789012:android:abcdef1234567890\";"),
				"the mobilesdk app id must be in the gate — a pure app-id class must not be skipped");
	}

	@Test
	void shortNumericAppIdClassPassesGate() {
		assertTrue(gated("\"1:100000:android:0a1b2c3d4e5f\""),
				"the app-id pattern (\\d:\\d{6,}:android:hex) must be in the gate regardless of length");
	}

	@Test
	void coreFirebaseMarkersStillGated() {
		assertTrue(gated("FirebaseDatabase.getInstance(url);"),
				"Firebase must remain gated (regression guard)");
		assertTrue(gated("String key = \"AIzaSyA0123456789_abcdefghijklmnopqrstu\";"),
				"AIza API key must remain gated (regression guard)");
		assertTrue(gated("FirebaseApp.initializeApp(ctx);"),
				"FirebaseApp must remain gated (regression guard)");
	}
}
