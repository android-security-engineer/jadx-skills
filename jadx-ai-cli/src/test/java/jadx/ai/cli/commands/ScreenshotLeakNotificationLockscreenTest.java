package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code notification_lockscreen_leak} detection in {@link ScreenshotLeakScanCommand}.
 *
 * <p>A Notification/NotificationChannel carrying sensitive content (OTP/auth/payment) but without
 * setVisibility(VISIBILITY_PRIVATE) / setLockscreenVisibility shows its full body on the lockscreen
 * — anyone holding the device reads the OTP/preview (CWE-200, MASVS MSTG-STORAGE-7). No detector
 * covered this; OtpInterceptionScan only used NotificationChannel as an interception heuristic, never
 * checked lockscreen visibility. The signal is class-level: NOTIFICATION_BUILD ∧ SENSITIVE_CONTENT ∧
 * ¬LOCKSCREEN_PRIVATE.
 */
class ScreenshotLeakNotificationLockscreenTest {

	private static final Pattern BUILD = ScreenshotLeakScanCommand.NOTIFICATION_BUILD;
	private static final Pattern PRIVATE = ScreenshotLeakScanCommand.LOCKSCREEN_PRIVATE;
	private static final Pattern SENSITIVE = ScreenshotLeakScanCommand.SENSITIVE_CONTENT;

	/** Mirrors execute()'s class-level notification-leak test. */
	private static boolean leaks(String code) {
		return BUILD.matcher(code).find()
				&& SENSITIVE.matcher(code).find()
				&& !PRIVATE.matcher(code).find();
	}

	@Test
	void otpNotificationWithoutVisibilityFires() {
		assertTrue(leaks("NotificationCompat.Builder builder = new NotificationCompat.Builder(ctx)\n"
				+ ".setContentText(\"Your OTP is 123456\");"),
				"an OTP notification with no setVisibility(VISIBILITY_PRIVATE) must fire");
	}

	@Test
	void authNotificationWithoutVisibilityFires() {
		assertTrue(leaks("NotificationChannel chan = new NotificationChannel(id, name, imp);\n"
				+ "chan.createNotificationChannel(manager);\n"
				+ "notif.setContentText(\"Login from new device: approve?\" + authToken);"),
				"an auth notification with no lockscreen redaction must fire");
	}

	@Test
	void notificationWithVisibilityPrivateDoesNotFire() {
		assertFalse(leaks("builder.setContentText(\"Your OTP is 123456\")\n"
				+ ".setVisibility(NotificationCompat.VISIBILITY_PRIVATE);"),
				"a notification that calls setVisibility(VISIBILITY_PRIVATE) must NOT fire — body redacted on lockscreen");
	}

	@Test
	void notificationWithVisibilitySecretDoesNotFire() {
		assertFalse(leaks("builder.setContentText(\"OTP 123456\")\n"
				+ "chan.setLockscreenVisibility(NotificationManager.IMPORTANCE_SECRET);"),
				"setLockscreenVisibility / VISIBILITY_SECRET must NOT fire — fully hidden on lockscreen");
	}

	@Test
	void nonSensitiveNotificationDoesNotFire() {
		assertFalse(leaks("builder.setContentText(\"Download complete\");"),
				"a non-sensitive notification must NOT fire — no OTP/auth/payment content");
	}

	@Test
	void noNotificationBuildDoesNotFire() {
		assertFalse(leaks("String otp = \"123456\"; sendOtp(otp);"),
				"OTP content with no Notification build must NOT fire the notification-leak rule");
	}
}
