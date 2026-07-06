package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the pin-set expiration comparison used to flag silently-disabled certificate pinning:
 * a clearly-past date is expired, a far-future date is not, and unparseable input stays null
 * (so a malformed expiration is never mistaken for an expired one).
 */
class NetworkSecurityConfigDateTest {

	@Test
	void pastDateIsExpired() {
		assertEquals(Boolean.TRUE, NetworkSecurityConfigCommand.isPastDate("2000-01-01"));
	}

	@Test
	void farFutureDateIsNotExpired() {
		assertEquals(Boolean.FALSE, NetworkSecurityConfigCommand.isPastDate("2999-12-31"));
	}

	@Test
	void unparseableDateIsNull() {
		assertNull(NetworkSecurityConfigCommand.isPastDate("not-a-date"));
		assertNull(NetworkSecurityConfigCommand.isPastDate("2020-13-40"));
	}

	@Test
	void whitespaceIsTrimmed() {
		assertTrue(Boolean.TRUE.equals(NetworkSecurityConfigCommand.isPastDate("  1999-06-15  ")));
	}
}
