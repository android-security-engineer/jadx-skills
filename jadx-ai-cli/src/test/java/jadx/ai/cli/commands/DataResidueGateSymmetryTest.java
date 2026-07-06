package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code RESIDUE_MARKER} gate / RULES-set symmetry in {@link DataResidueScanCommand}.
 *
 * <p>execute() skips any class that does not match {@code RESIDUE_MARKER}, so every rule's anchor
 * must also appear in the gate. The gate was out of sync: the {@code sdcard_direct} rule matches
 * {@code /storage/emulated/0/...} — the modern default external-storage path — but the gate only had
 * {@code /sdcard/} and {@code /mnt/sdcard}. A class with a hard-coded {@code /storage/emulated/0/...}
 * path literal and NO {@code getExternalStorage*}/{@code Environment} call was skipped and
 * {@code sdcard_direct} (the high-severity "bypasses the per-app sandbox" finding) never fired.
 */
class DataResidueGateSymmetryTest {

	private static boolean gated(String code) {
		return DataResidueScanCommand.RESIDUE_MARKER.matcher(code).find();
	}

	@Test
	void storageEmulatedFullPathClassPassesGate() {
		assertTrue(gated("File f = new File(\"/storage/emulated/0/MyApp/cache.dat\");"),
				"/storage/emulated/0/ path literal must be in the gate — a pure path-literal class must not be skipped");
	}

	@Test
	void storageEmulatedQuotedPrefixClassPassesGate() {
		assertTrue(gated("String root = \"/storage/emulated/0\";"),
				"the \"/storage/emulated quoted prefix must be in the gate");
	}

	@Test
	void sdcardAndMntStillGated() {
		assertTrue(gated("new File(\"/sdcard/data\");"),
				"/sdcard/ must remain gated (regression guard)");
		assertTrue(gated("new File(\"/mnt/sdcard/data\");"),
				"/mnt/sdcard must remain gated (regression guard)");
	}

	@Test
	void nonResidueClassNotGated() {
		assertFalse(gated("int x = 1 + 2;"),
				"a class with no residue marker must not pass the gate");
	}
}
