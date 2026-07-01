package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code flag_secure_absent} implementation in {@link ScreenCaptureScanCommand}.
 *
 * <p>The class doc promised a {@code flag_secure_absent} finding but {@code execute()} never emitted
 * it, and {@code hasFlagSecure} used the bare {@code FLAG_SECURE} literal (so a comment mentioning
 * FLAG_SECURE suppressed the absent finding). The fix: emit {@code flag_secure_absent} when an
 * Activity class does not apply FLAG_SECURE via a real {@code setFlags/addFlags} call.
 */
class ScreenCaptureFlagSecureAbsentTest {

	/** Mirrors execute()'s class-level decision for flag_secure_absent. */
	private static boolean shouldReportAbsent(String code) {
		boolean classIsActivity = ScreenCaptureScanCommand.ACTIVITY_MARKER.matcher(code).find();
		boolean classHasFlagSecure = ScreenCaptureScanCommand.FLAG_SECURE_ON_WINDOW.matcher(code).find();
		return classIsActivity && !classHasFlagSecure;
	}

	@Test
	void activityWithoutFlagSecureReportsAbsent() {
		String code = "public class MainActivity extends AppCompatActivity {\n"
				+ "  protected void onCreate(Bundle b) { setContentView(R.layout.main); }\n"
				+ "}";
		assertTrue(shouldReportAbsent(code),
				"an Activity that never applies FLAG_SECURE must report flag_secure_absent");
	}

	@Test
	void activityWithRealFlagSecureDoesNotReportAbsent() {
		String code = "public class SensitiveActivity extends AppCompatActivity {\n"
				+ "  protected void onCreate(Bundle b) {\n"
				+ "    getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, FLAG_SECURE);\n"
				+ "  }\n"
				+ "}";
		assertFalse(shouldReportAbsent(code),
				"an Activity that applies FLAG_SECURE via setFlags is defended — no absent finding");
	}

	@Test
	void activityWithAddFlagsDoesNotReportAbsent() {
		String code = "public class X extends Activity { void f(){ getWindow().addFlags(FLAG_SECURE); } }";
		assertFalse(shouldReportAbsent(code),
				"addFlags(FLAG_SECURE) is a real application — no absent finding");
	}

	@Test
	void commentMentioningFlagSecureStillReportsAbsent() {
		// The FP being fixed: a comment / TODO mentioning FLAG_SECURE must NOT count as defended.
		String code = "public class MainActivity extends AppCompatActivity {\n"
				+ "  // TODO: add FLAG_SECURE to prevent screenshots\n"
				+ "  protected void onCreate(Bundle b) { setContentView(R.layout.main); }\n"
				+ "}";
		assertTrue(shouldReportAbsent(code),
				"a bare comment mentioning FLAG_SECURE is not a defence — absent finding still fires");
	}

	@Test
	void nonActivityClassDoesNotReportAbsent() {
		// A plain helper class is not an Activity window — not a FLAG_SECURE candidate.
		String code = "public class UrlUtils { static String build(String s){ return s; } }";
		assertFalse(shouldReportAbsent(code),
				"a non-Activity class is not a FLAG_SECURE candidate");
	}

	@Test
	void activitySetFlagsWithoutFlagSecureReportsAbsent() {
		// setFlags called but NOT with FLAG_SECURE (e.g. setFlags(FULLSCREEN, FULLSCREEN)) — not defended.
		String code = "public class MainActivity extends Activity {\n"
				+ "  void f(){ getWindow().setFlags(FULLSCREEN, FULLSCREEN); }\n"
				+ "}";
		assertTrue(shouldReportAbsent(code),
				"setFlags without FLAG_SECURE is not a defence — absent finding fires");
	}
}
