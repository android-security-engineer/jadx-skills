package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code AD_MARKER} gate / RULES-set symmetry in {@link AdFraudScanCommand}.
 *
 * <p>execute() skips any class that does not match {@code AD_MARKER}, so every rule's anchor must
 * also appear in the gate. The gate was out of sync: the {@code click_fraud} rule's custom-named
 * anchors ({@code simulateAdClick}/{@code adClickUrl}/{@code AdClickHandler}/{@code autoClickAd}/
 * {@code adClickRedirect}) are deliberately-named helper methods/fields with NO Ad SDK type
 * reference, so a dedicated fraud-helper class was skipped and {@code click_fraud} never fired.
 */
class AdFraudGateSymmetryTest {

	private static boolean gated(String code) {
		return AdFraudScanCommand.AD_MARKER.matcher(code).find();
	}

	@Test
	void simulateAdClickClassPassesGate() {
		assertTrue(gated("private void simulateAdClick() { view.performClick(); }"),
				"simulateAdClick must be in the gate — a pure fraud-helper class must not be skipped");
	}

	@Test
	void adClickUrlClassPassesGate() {
		assertTrue(gated("String adClickUrl = baseUrl + \"/click\";"),
				"adClickUrl must be in the gate — a fraud-helper field must not be skipped");
	}

	@Test
	void adClickHandlerClassPassesGate() {
		assertTrue(gated("class AdClickHandler implements Runnable { }"),
				"AdClickHandler must be in the gate — a fraud-helper class name must not be skipped");
	}

	@Test
	void autoClickAdClassPassesGate() {
		assertTrue(gated("void autoClickAd(View ad) { ad.performClick(); }"),
				"autoClickAd must be in the gate — a fraud-helper method must not be skipped");
	}

	@Test
	void adClickRedirectClassPassesGate() {
		assertTrue(gated("Intent i = new Intent(adClickRedirect);"),
				"adClickRedirect must be in the gate — a fraud-helper anchor must not be skipped");
	}

	@Test
	void performClickStillGated() {
		assertTrue(gated("btn.performClick();"),
				"performClick must remain gated (regression guard)");
	}

	@Test
	void nonAdClassNotGated() {
		assertFalse(gated("int x = computeScore();"),
				"a class with no ad marker must not pass the gate");
	}
}
