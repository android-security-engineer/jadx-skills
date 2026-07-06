package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards two real-world Intent-redirection sinks that were silently missed.
 *
 * <ol>
 *   <li><b>{@code *AsUser} broadcast variants</b> — {@code sendBroadcastAsUser} /
 *       {@code sendOrderedBroadcastAsUser} / {@code sendStickyBroadcastAsUser} take a
 *       {@code UserHandle} and propagate the extracted nested Intent (even cross-user). The bare
 *       {@code sendBroadcast\s*\(} term did NOT match them (the char after {@code sendBroadcast} is
 *       {@code A}, not {@code (}) — exactly the gap the sticky forms had. Now full
 *       {@link IntentRedirectionScanCommand#LAUNCH_SINK} members.</li>
 *   <li><b>PendingIntent / TaskStackBuilder wrapping</b> — extracting a nested Intent and building a
 *       {@code PendingIntent.get*} (or {@code TaskStackBuilder.makePendingIntent}) is the Google
 *       Play-flagged CWE-927 variant: the caller triggers the PendingIntent with this app's identity.
 *       These are NOT in {@code LAUNCH_SINK} (a class-level heuristic can't tell a PendingIntent built
 *       from the extracted Intent vs a self-made Notification Intent); they get a distinct
 *       {@link IntentRedirectionScanCommand#PENDING_INTENT_SINK} and a separate medium finding.</li>
 * </ol>
 */
class IntentRedirectionAsUserAndPendingSinkTest {

	private static boolean launchSinkOn(String line) {
		return IntentRedirectionScanCommand.LAUNCH_SINK.matcher(line).find();
	}

	private static boolean pendingSinkOn(String line) {
		return IntentRedirectionScanCommand.PENDING_INTENT_SINK.matcher(line).find();
	}

	// --- 1. *AsUser broadcast variants are full high sinks ---

	@Test
	void sendBroadcastAsUserFires() {
		assertTrue(launchSinkOn("sendBroadcastAsUser(inner, UserHandle.ALL);"),
				"sendBroadcastAsUser propagates the extracted Intent — must be a high redirect sink");
	}

	@Test
	void sendOrderedBroadcastAsUserFires() {
		assertTrue(launchSinkOn("sendOrderedBroadcastAsUser(inner, UserHandle.ALL, null, null, 0, null, null);"),
				"sendOrderedBroadcastAsUser must be a high redirect sink");
	}

	@Test
	void sendStickyBroadcastAsUserFires() {
		assertTrue(launchSinkOn("sendStickyBroadcastAsUser(inner, UserHandle.ALL);"),
				"sendStickyBroadcastAsUser must be a high redirect sink");
	}

	@Test
	void plainSendBroadcastStillFires() {
		assertTrue(launchSinkOn("sendBroadcast(inner);"),
				"plain sendBroadcast must still be a sink (regression guard)");
	}

	@Test
	void nonBroadcastCallDoesNotFire() {
		assertFalse(launchSinkOn("String action = intent.getAction();"),
				"getAction is not a launch — must not be a sink");
	}

	// --- 2. PendingIntent / TaskStackBuilder wrapping is a distinct medium sink ---

	@Test
	void pendingIntentGetActivityFires() {
		assertTrue(pendingSinkOn("PendingIntent.getActivity(this, 0, nested, 0);"),
				"PendingIntent.getActivity wrapping an Intent must be a pending_intent_redirection sink");
	}

	@Test
	void pendingIntentGetActivitiesFires() {
		assertTrue(pendingSinkOn("PendingIntent.getActivities(this, 0, new Intent[]{nested}, 0);"),
				"PendingIntent.getActivities (plural) must be a pending sink");
	}

	@Test
	void pendingIntentGetBroadcastFires() {
		assertTrue(pendingSinkOn("PendingIntent.getBroadcast(this, 0, nested, 0);"),
				"PendingIntent.getBroadcast must be a pending sink");
	}

	@Test
	void pendingIntentGetServiceFires() {
		assertTrue(pendingSinkOn("PendingIntent.getService(this, 0, nested, 0);"),
				"PendingIntent.getService must be a pending sink");
	}

	@Test
	void pendingIntentGetForegroundServiceFires() {
		assertTrue(pendingSinkOn("PendingIntent.getForegroundService(this, 0, nested, 0);"),
				"PendingIntent.getForegroundService must be a pending sink");
	}

	@Test
	void taskStackBuilderMakePendingIntentFires() {
		assertTrue(pendingSinkOn("TaskStackBuilder.create(this).addNextIntent(nested).makePendingIntent(0);"),
				"TaskStackBuilder.makePendingIntent chaining an Intent must be a pending sink");
	}

	@Test
	void pendingIntentSinkIsNotALaunchSink() {
		// Critical: PendingIntent.get* must NOT also be in LAUNCH_SINK, or it would double-fire as
		// intent_redirection/high and pollute the high pool with Notification FPs.
		assertFalse(launchSinkOn("PendingIntent.getActivity(this, 0, new Intent(...), 0);"),
				"PendingIntent.get* must be a distinct pending sink, NOT a high launch sink");
	}

	@Test
	void nonSinkCallDoesNotFire() {
		assertFalse(pendingSinkOn("startActivity(nested);"),
				"startActivity is a launch sink, not a pending sink");
		assertFalse(pendingSinkOn("Intent i = new Intent(this, Other.class);"),
				"Intent construction is not a pending sink");
	}
}
