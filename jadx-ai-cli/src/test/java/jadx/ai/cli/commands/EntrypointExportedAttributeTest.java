package jadx.ai.cli.commands;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code android:exported} surfacing in {@link EntrypointScanCommand}.
 *
 * <p>The dead {@code MANIFEST_COMPONENT} regex captured an {@code android:exported} group but never
 * surfaced it — every manifest entrypoint was reported without its exported state, so attack-surface
 * triage could not distinguish an exported service/receiver/provider (reachable by other apps) from
 * an internal one. {@code parseManifestEntrypoints} now attaches {@code exported="true"/"false"} to
 * each component when declared.
 */
class EntrypointExportedAttributeTest {

	private static Map<String, Object> firstOfKind(List<Map<String, Object>> eps, String kind) {
		return eps.stream().filter(e -> kind.equals(e.get("kind"))).findFirst().orElseThrow();
	}

	@Test
	void exportedServiceSurfacesTrue() {
		String xml = "<service android:name=\".SmsSvc\" android:exported=\"true\"/>";
		List<Map<String, Object>> eps = EntrypointScanCommand.parseManifestEntrypoints(xml);
		assertEquals("true", firstOfKind(eps, "service").get("exported"),
				"an exported service must surface exported=\"true\"");
	}

	@Test
	void internalServiceSurfacesFalse() {
		String xml = "<service android:name=\".InternalSvc\" android:exported=\"false\"/>";
		List<Map<String, Object>> eps = EntrypointScanCommand.parseManifestEntrypoints(xml);
		assertEquals("false", firstOfKind(eps, "service").get("exported"),
				"an explicitly internal service must surface exported=\"false\"");
	}

	@Test
	void exportedAbsentMeansNoField() {
		// A component with no android:exported attribute — absent is itself significant (implicit-export
		// rules on older targetSdk), so the field is omitted rather than defaulted.
		String xml = "<receiver android:name=\".BootRcv\"/>";
		List<Map<String, Object>> eps = EntrypointScanCommand.parseManifestEntrypoints(xml);
		assertNull(firstOfKind(eps, "receiver").get("exported"),
				"a component with no exported attr must not carry an exported field");
	}

	@Test
	void exportedProviderSurfacesTrue() {
		String xml = "<provider android:name=\".FileProv\" android:exported=\"true\" android:authorities=\"x\"/>";
		List<Map<String, Object>> eps = EntrypointScanCommand.parseManifestEntrypoints(xml);
		assertEquals("true", firstOfKind(eps, "provider").get("exported"),
				"an exported provider must surface exported=\"true\"");
	}

	@Test
	void launcherActivitySurfacesExported() {
		String xml = "<activity android:name=\".Main\" android:exported=\"true\">"
				+ "<intent-filter><action android:name=\"android.intent.action.MAIN\"/>"
				+ "<category android:name=\"android.intent.category.LAUNCHER\"/></intent-filter>"
				+ "</activity>";
		List<Map<String, Object>> eps = EntrypointScanCommand.parseManifestEntrypoints(xml);
		assertEquals("true", firstOfKind(eps, "launcher-activity").get("exported"),
				"the launcher activity must surface its exported flag");
	}

	@Test
	void activityAliasSurfacesExported() {
		String xml = "<activity-alias android:name=\".Alias\" android:targetActivity=\".Main\" android:exported=\"true\"/>";
		List<Map<String, Object>> eps = EntrypointScanCommand.parseManifestEntrypoints(xml);
		assertEquals("true", firstOfKind(eps, "activity-alias").get("exported"),
				"an exported activity-alias must surface exported=\"true\"");
	}

	@Test
	void exportedNotLeakedAcrossComponents() {
		// A self-closing internal receiver followed by an exported service — the receiver must NOT
		// inherit the service's exported="true" (the split-based block extraction must stay local).
		String xml = "<receiver android:name=\".R\"/> "
				+ "<service android:name=\".S\" android:exported=\"true\"/>";
		List<Map<String, Object>> eps = EntrypointScanCommand.parseManifestEntrypoints(xml);
		assertNull(firstOfKind(eps, "receiver").get("exported"),
				"the receiver has no exported attr and must not inherit the next service's flag");
		assertEquals("true", firstOfKind(eps, "service").get("exported"));
	}

	@Test
	void applicationClassHasNoExportedField() {
		// <application> is not a component with an exported attr — it must not get one.
		String xml = "<application android:name=\".App\" android:exported=\"true\">";
		List<Map<String, Object>> eps = EntrypointScanCommand.parseManifestEntrypoints(xml);
		assertTrue(eps.stream().anyMatch(e -> "application".equals(e.get("kind"))),
				"the application class must be parsed");
		assertFalse(firstOfKind(eps, "application").containsKey("exported"),
				"<application> is not an exported component — no exported field");
	}
}
