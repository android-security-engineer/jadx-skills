package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code setXIncludeAware(true)} detection in {@link XxeScanCommand}.
 *
 * <p>{@code HARDENED} already recognised {@code setXIncludeAware(false)} as hardening, but the
 * explicit-danger detector only matched {@code setExpandEntityReferences(true)} — so
 * {@code setXIncludeAware(true)}, which enables XInclude processing (an attacker can pull in external
 * files via {@code <xi:include href="...">}), was not flagged. Symmetric gap: the safe form detected,
 * the dangerous form not.
 */
class XxeExplicitDangerTest {

	private static boolean danger(String line) {
		return XxeScanCommand.isXxeExplicitDanger(line);
	}

	@Test
	void setExpandEntityReferencesTrueStillFires() {
		assertTrue(danger("factory.setExpandEntityReferences(true);"),
				"setExpandEntityReferences(true) must still fire");
	}

	@Test
	void setXIncludeAwareTrueNowFires() {
		assertTrue(danger("dbf.setXIncludeAware(true);"),
				"setXIncludeAware(true) enables XInclude (external-file read) — must fire high");
	}

	@Test
	void setXIncludeAwareFalseDoesNotFire() {
		assertFalse(danger("dbf.setXIncludeAware(false);"),
				"setXIncludeAware(false) is hardening, not danger");
	}

	@Test
	void setExpandEntityReferencesFalseDoesNotFire() {
		assertFalse(danger("factory.setExpandEntityReferences(false);"),
				"setExpandEntityReferences(false) is hardening, not danger");
	}

	@Test
	void unrelatedXIncludeMentionDoesNotFire() {
		// A bare boolean assignment is not the dangerous call (no setXIncludeAware( call).
		assertFalse(danger("boolean xIncludeAware = true;"),
				"a bare boolean assignment is not the dangerous call");
		assertFalse(danger("Log.i(TAG, \"xinclude=\" + xIncludeAware);"),
				"logging a variable named xIncludeAware is not the dangerous call");
	}

	@Test
	void xincludeAwareChainedTrueFires() {
		assertTrue(danger("DocumentBuilderFactory.newInstance().setXIncludeAware(true);"),
				"chained setXIncludeAware(true) must fire");
	}
}
