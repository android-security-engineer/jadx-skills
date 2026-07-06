package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the literal-form deepening of {@code MODE_WORLD_READABLE} / {@code MODE_WORLD_WRITEABLE}
 * detection in {@link InsecureFileIoScanCommand}.
 *
 * <p>{@code Context.MODE_WORLD_READABLE} (=1) and {@code MODE_WORLD_WRITEABLE} (=2) are
 * {@code static final int} constants, folded to their integer literals by javac/d8, so jadx
 * decompiles {@code openFileOutput("f", MODE_WORLD_READABLE)} as {@code openFileOutput("f", 1)}
 * and the identifiers NEVER appear. The old identifier-only arms were dead code — the
 * {@code world_readable_file} / {@code world_writable_file} findings fired only on the rarer
 * {@code setReadable(true,false)} / {@code chmod 644} forms. Verified against actual
 * javac&#8594;d8&#8594;jadx output ({@code context.openFileOutput("f", 1);}).
 */
class InsecureFileIoWorldReadableLiteralTest {

	private static final java.util.regex.Pattern READABLE = InsecureFileIoScanCommand.WORLD_READABLE;
	private static final java.util.regex.Pattern WRITABLE = InsecureFileIoScanCommand.WORLD_WRITABLE;

	// --- openFileOutput(name, <modeLiteral>) ---

	@Test
	void openFileOutputMode1FiresReadable() {
		assertTrue(READABLE.matcher("context.openFileOutput(\"f\", 1);").find(),
				"openFileOutput(\"f\", 1) (MODE_WORLD_READABLE) — the real jadx form — must fire");
	}

	@Test
	void openFileOutputMode3FiresReadable() {
		// mode 3 = MODE_WORLD_READABLE | MODE_WORLD_WRITEABLE
		assertTrue(READABLE.matcher("context.openFileOutput(\"f\", 3);").find(),
				"openFileOutput(\"f\", 3) (READABLE|WRITABLE) must fire the readable rule");
	}

	@Test
	void openFileOutputMode2FiresWritable() {
		assertTrue(WRITABLE.matcher("context.openFileOutput(\"g\", 2);").find(),
				"openFileOutput(\"g\", 2) (MODE_WORLD_WRITEABLE) must fire the writable rule");
	}

	@Test
	void openFileOutputMode3FiresWritable() {
		assertTrue(WRITABLE.matcher("context.openFileOutput(\"f\", 3);").find(),
				"openFileOutput(\"f\", 3) (READABLE|WRITABLE) must fire the writable rule");
	}

	// --- getSharedPreferences / getDir ---

	@Test
	void getSharedPreferencesMode1FiresReadable() {
		assertTrue(READABLE.matcher("getSharedPreferences(\"x\", 1);").find(),
				"getSharedPreferences(\"x\", 1) (MODE_WORLD_READABLE) must fire");
	}

	@Test
	void getDirMode2FiresWritable() {
		assertTrue(WRITABLE.matcher("getDir(\"d\", 2);").find(),
				"getDir(\"d\", 2) (MODE_WORLD_WRITEABLE) must fire");
	}

	// --- the safe MODE_PRIVATE (0) must NOT fire ---

	@Test
	void openFileOutputMode0DoesNotFire() {
		assertFalse(READABLE.matcher("context.openFileOutput(\"h\", 0);").find(),
				"openFileOutput(\"h\", 0) (MODE_PRIVATE) must NOT fire the readable rule");
		assertFalse(WRITABLE.matcher("context.openFileOutput(\"h\", 0);").find(),
				"openFileOutput(\"h\", 0) (MODE_PRIVATE) must NOT fire the writable rule");
	}

	// --- identifier arms remain (source-form) ---

	@Test
	void identifierFormStillFires() {
		assertTrue(READABLE.matcher("openFileOutput(\"f\", Context.MODE_WORLD_READABLE);").find(),
				"the identifier form must still fire");
		assertTrue(WRITABLE.matcher("openFileOutput(\"g\", MODE_WORLD_WRITEABLE);").find(),
				"the identifier form must still fire");
	}

	// --- false-positive guards ---

	@Test
	void bareOneNotInCallDoesNotFire() {
		assertFalse(READABLE.matcher("int mode = 1;").find(),
				"a bare 1 NOT in openFileOutput/getSharedPreferences/getDir must NOT fire");
	}

	@Test
	void setReadableStillFires() {
		assertTrue(READABLE.matcher("file.setReadable(true, false);").find(),
				"the setReadable(true, false) arm must still fire (non-folded)");
	}
}
