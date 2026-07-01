package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression guard for the bare-{@code "<intent-filter>"} bug: an opening intent-filter tag carrying
 * attributes — {@code android:autoVerify="true"} (App Links) or {@code android:priority="..."} — must
 * still register as "has an intent-filter". Both {@link UnsafeExportScanCommand} (implicit-export
 * detection) and {@link DeeplinkScanCommand} (which most cares about verified App Links) previously
 * used a literal {@code "<intent-filter>"} check that silently dropped these forms.
 */
class IntentFilterAttributeTest {

	private static final String AUTOVERIFY =
			"<activity android:name=\".Deep\"><intent-filter android:autoVerify=\"true\">"
					+ "<action android:name=\"android.intent.action.VIEW\"/>"
					+ "<data android:scheme=\"https\" android:host=\"example.com\"/></intent-filter></activity>";
	private static final String PRIORITY =
			"<receiver android:name=\".R\"><intent-filter android:priority=\"999\">"
					+ "<action android:name=\"android.intent.action.BOOT_COMPLETED\"/></intent-filter></receiver>";
	private static final String BARE =
			"<service android:name=\".S\"><intent-filter>"
					+ "<action android:name=\"x\"/></intent-filter></service>";
	private static final String NONE =
			"<service android:name=\".S\"></service>";

	@Test
	void unsafeExportSeesAttributedIntentFilters() {
		assertTrue(UnsafeExportScanCommand.hasIntentFilter(AUTOVERIFY), "autoVerify filter must count");
		assertTrue(UnsafeExportScanCommand.hasIntentFilter(PRIORITY), "priority filter must count");
		assertTrue(UnsafeExportScanCommand.hasIntentFilter(BARE), "bare filter must count");
		assertFalse(UnsafeExportScanCommand.hasIntentFilter(NONE), "no filter must not count");
	}

	@Test
	void deeplinkSeesAttributedIntentFilters() {
		assertTrue(DeeplinkScanCommand.hasIntentFilter(AUTOVERIFY), "autoVerify is the App Links form");
		assertTrue(DeeplinkScanCommand.hasIntentFilter(PRIORITY));
		assertTrue(DeeplinkScanCommand.hasIntentFilter(BARE));
		assertFalse(DeeplinkScanCommand.hasIntentFilter(NONE));
	}

	@Test
	void bareTagIsNotConfusedWithUnrelatedText() {
		assertFalse(UnsafeExportScanCommand.hasIntentFilter("<intent-filter-helper/>"),
				"a hyphenated lookalike tag must not match");
	}
}
