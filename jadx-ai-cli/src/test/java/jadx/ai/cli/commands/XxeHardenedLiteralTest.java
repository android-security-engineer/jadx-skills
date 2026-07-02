package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the literal-form deepening of {@link XxeScanCommand#HARDENED}.
 *
 * <p>{@code XMLConstants.FEATURE_SECURE_PROCESSING}, {@code ACCESS_EXTERNAL_DTD}, and
 * {@code ACCESS_EXTERNAL_SCHEMA} are {@code static final String} constants, folded to their string
 * literal values by javac/d8, so jadx emits {@code setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true)}
 * and the identifiers NEVER appear. The old identifier-only {@code HARDENED} arms were dead code,
 * so a parser hardened ONLY via FEATURE_SECURE_PROCESSING was misclassified as unhardened — a
 * false-positive amplifier ({@code xxe_unhardened_parser} high on safe code). Verified against
 * actual javac&#8594;d8&#8594;jadx output.
 */
class XxeHardenedLiteralTest {

	private static final java.util.regex.Pattern HARDENED = XxeScanCommand.HARDENED;

	// --- the real jadx-decompiled string-literal-value forms ---

	@Test
	void secureProcessingLiteralFires() {
		assertTrue(HARDENED.matcher(
				"dbf.setFeature(\"http://javax.xml.XMLConstants/feature/secure-processing\", true);").find(),
				"the secure-processing literal URL (FEATURE_SECURE_PROCESSING folded) must fire");
	}

	@Test
	void accessExternalDtdLiteralFires() {
		assertTrue(HARDENED.matcher(
				"dbf.setAttribute(\"http://apache.org/xml/properties/accessExternalDTD\", \"\");").find(),
				"the accessExternalDTD literal URL (ACCESS_EXTERNAL_DTD folded) must fire");
	}

	@Test
	void accessExternalSchemaLiteralFires() {
		assertTrue(HARDENED.matcher(
				"dbf.setAttribute(\"http://apache.org/xml/properties/accessExternalSchema\", \"\");").find(),
				"the accessExternalSchema literal URL (ACCESS_EXTERNAL_SCHEMA folded) must fire");
	}

	// --- disallow-doctype-decl stays (already a literal value) ---

	@Test
	void disallowDoctypeDeclFires() {
		assertTrue(HARDENED.matcher(
				"dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);").find(),
				"disallow-doctype-decl (already a literal value) must fire");
	}

	// --- identifier arms remain (source-form / a constant jadx did not fold) ---

	@Test
	void identifierFormStillFires() {
		assertTrue(HARDENED.matcher("dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);").find(),
				"the identifier form must still fire");
		assertTrue(HARDENED.matcher("dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\");").find(),
				"the ACCESS_EXTERNAL_DTD identifier form must still fire");
	}

	// --- the false-positive-amplification case: a FEATURE_SECURE_PROCESSING-hardened parser is NOT unhardened ---

	@Test
	void secureProcessingHardenedNotUnhardened() {
		// This is the case the old dead-code pattern broke: a parser hardened via secure-processing,
		// decompiled to the literal URL. classHardened must now be true.
		String code = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
				+ "dbf.setFeature(\"http://javax.xml.XMLConstants/feature/secure-processing\", true);\n";
		assertTrue(XxeScanCommand.HARDENED.matcher(code).find(),
				"a secure-processing-hardened parser must be recognized as hardened (literal URL form)");
	}

	// --- false-positive guards ---

	@Test
	void unrelatedStringDoesNotFire() {
		assertFalse(HARDENED.matcher("dbf.setFeature(\"http://example.com/foo\", true);").find(),
				"an unrelated feature URL must NOT fire the hardened rule");
	}
}
