package jadx.ai.cli.commands;

import java.util.regex.Matcher;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards two parsing fixes in {@link ManifestSecurityAuditCommand}:
 * <ol>
 *   <li>{@code findComponentEnd} on a self-closing component must end at that component's own
 *       {@code >} — previously it scanned past self-closing tags and absorbed following components'
 *       attributes (cross-component exported/intent-filter misattribution).</li>
 *   <li>{@code <activity-alias>} must NOT be matched as an {@code activity} — {@code activity} is a
 *       prefix of {@code activity-alias}, so the old {@code activity[^>]+} form mis-typed every
 *       activity-alias as an activity. activity-alias now has its own pattern/type.</li>
 * </ol>
 */
class ManifestSecurityAuditParseTest {

	@Test
	void selfClosingComponentDoesNotOverreach() {
		// A self-closing activity immediately followed by an exported service. The activity's block
		// must NOT include the service's exported="true".
		String xml = "<activity android:name=\".Main\"/> "
				+ "<service android:name=\".S\" android:exported=\"true\"/>";
		int start = xml.indexOf("<activity");
		int end = ManifestSecurityAuditCommand.findComponentEnd(xml, start);
		String block = xml.substring(start, end);
		assertFalse(block.contains("android:exported=\"true\""),
				"self-closing activity block must not absorb the following service's exported flag");
		assertTrue(block.endsWith("/>") || block.endsWith(">"),
				"self-closing activity block ends at its own >");
	}

	@Test
	void blockComponentWithNestedChildrenEndsAtMatchingClose() {
		// A block activity with a nested intent-filter must end after </activity>, not at the first
		// inner close tag.
		String xml = "<activity android:name=\".Main\" android:exported=\"true\">"
				+ "<intent-filter><action android:name=\"android.intent.action.MAIN\"/></intent-filter>"
				+ "</activity> <service android:name=\".S\"/>";
		int start = xml.indexOf("<activity");
		int end = ManifestSecurityAuditCommand.findComponentEnd(xml, start);
		String block = xml.substring(start, end);
		assertTrue(block.contains("</activity>"), "block must include its close tag");
		assertFalse(block.contains("<service"), "block must not run into the following service");
	}

	@Test
	void activityPatternDoesNotMatchActivityAlias() {
		Matcher m = ManifestSecurityAuditCommand.ACTIVITY_PATTERN.matcher(
				"<activity-alias android:name=\".Alias\" targetActivity=\".Real\"/>");
		assertFalse(m.find(),
				"an activity-alias must NOT be matched by the activity pattern (it has its own type)");
	}

	@Test
	void activityPatternStillMatchesPlainActivity() {
		Matcher m = ManifestSecurityAuditCommand.ACTIVITY_PATTERN.matcher(
				"<activity android:name=\".Main\" android:exported=\"true\">");
		assertTrue(m.find(), "a plain activity must still match");
		assertEquals(".Main", m.group(1));
	}

	@Test
	void activityAliasPatternMatchesAlias() {
		Matcher m = ManifestSecurityAuditCommand.ACTIVITY_ALIAS_PATTERN.matcher(
				"<activity-alias android:name=\".Alias\" targetActivity=\".Real\"/>");
		assertTrue(m.find(), "activity-alias is recognized under its own type");
		assertEquals(".Alias", m.group(1));
	}

	@Test
	void selfClosingActivityAliasDoesNotOverreach() {
		String xml = "<activity-alias android:name=\".Alias\"/> "
				+ "<receiver android:name=\".R\" android:exported=\"true\"/>";
		int start = xml.indexOf("<activity-alias");
		int end = ManifestSecurityAuditCommand.findComponentEnd(xml, start);
		String block = xml.substring(start, end);
		assertFalse(block.contains("android:exported=\"true\""),
				"self-closing activity-alias block must not absorb the following receiver's exported flag");
	}
}
