package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the sticky-broadcast sinks added to {@link IntentRedirectionScanCommand#LAUNCH_SINK}.
 *
 * <p>A sticky broadcast ({@code sendStickyBroadcast}/{@code sendStickyOrderedBroadcast}) of an
 * extracted nested Intent proxies access to non-exported components just as a plain
 * {@code sendBroadcast} does — the launched Intent is still the attacker-supplied one. The old
 * sink set listed only {@code sendBroadcast}/{@code sendOrderedBroadcast}, so a redirect that
 * rebroadcast via the sticky variants was silently missed.
 */
class IntentRedirectionStickySinkTest {

	private static boolean sinkOn(String line) {
		return IntentRedirectionScanCommand.LAUNCH_SINK.matcher(line).find();
	}

	@Test
	void startActivitySinkFires() {
		assertTrue(sinkOn("startActivity(inner);"), "startActivity must be a redirect sink (regression guard)");
		assertTrue(sinkOn("startActivityForResult(inner, 0);"), "startActivityForResult must be a sink");
		assertTrue(sinkOn("startService(inner);"), "startService must be a sink");
	}

	@Test
	void plainBroadcastSinkFires() {
		assertTrue(sinkOn("sendBroadcast(inner);"), "sendBroadcast must be a sink (regression guard)");
		assertTrue(sinkOn("sendOrderedBroadcast(inner, null);"), "sendOrderedBroadcast must be a sink");
	}

	@Test
	void stickyBroadcastSinkFires() {
		assertTrue(sinkOn("sendStickyBroadcast(inner);"),
				"sendStickyBroadcast launches the extracted Intent — must be a redirect sink");
		assertTrue(sinkOn("sendStickyOrderedBroadcast(inner, null, null, 0, null, null);"),
				"sendStickyOrderedBroadcast must be a redirect sink");
	}

	@Test
	void bindServiceSinkFires() {
		assertTrue(sinkOn("bindService(inner, conn, 0);"), "bindService with an Intent must be a sink");
	}

	@Test
	void nonLaunchCallDoesNotFire() {
		assertFalse(sinkOn("Intent i = getIntent();"),
				"getIntent is not a launch — must not be a sink");
		assertFalse(sinkOn("String action = intent.getAction();"),
				"getAction is not a launch — must not be a sink");
	}
}
