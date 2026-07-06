package jadx.ai.cli.commands;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the {@code file_provider_misconfig} resource-level detection in
 * {@link InsecureFileIoScanCommand} — the overly-broad FileProvider path XML check.
 *
 * <p>The old {@code file_provider_misconfig} rule only flagged FileProvider *usage* in code with an
 * info "verify path config" note — it never read {@code res/xml/file_paths.xml}, so a real
 * {@code <root-path path=""/>} or {@code <external-path ... path="/"/>} exposure (any URI holder
 * reads the filesystem root / external storage, CWE-22/CWE-732) passed silently. The new
 * {@link InsecureFileIoScanCommand#BROAD_FILE_PATH} pattern is matched against decoded XML resources.
 */
class InsecureFileIoBroadFilePathTest {

	private static final Pattern BROAD = InsecureFileIoScanCommand.BROAD_FILE_PATH;

	private static boolean fires(String xml) {
		return BROAD.matcher(xml).find();
	}

	@Test
	void rootPathFires() {
		assertTrue(fires("<paths><root-path name=\"root\" path=\"\"/></paths>"),
				"<root-path> exposes the entire filesystem root — must fire");
	}

	@Test
	void externalPathRootFires() {
		assertTrue(fires("<external-path name=\"ext\" path=\"/\"/>"),
				"<external-path path=\"/\"> exposes all of external storage — must fire");
	}

	@Test
	void externalPathEmptyFires() {
		assertTrue(fires("<external-files-path name=\"ef\" path=\"\"/>"),
				"<external-files-path path=\"\"> exposes all external files — must fire");
	}

	@Test
	void cachePathRootFires() {
		assertTrue(fires("<cache-path name=\"c\" path=\"/\"/>"),
				"<cache-path path=\"/\"> exposes the cache root — must fire");
	}

	@Test
	void grantAllPermissionsFires() {
		assertTrue(fires("<provider grant-all-permissions=\"true\"/>"),
				"grant-all-permissions widens every granted URI — must fire");
	}

	@Test
	void scopedPathDoesNotFire() {
		assertFalse(fires("<files-path name=\"imgs\" path=\"images/\"/>"),
				"a scoped files-path (path=\"images/\") must NOT fire — it is a legitimate narrow grant");
		assertFalse(fires("<external-path name=\"ext\" path=\"MyAppPics/\"/>"),
				"a scoped external-path (path=\"MyAppPics/\") must NOT fire");
	}

	@Test
	void plainPathsWrapperDoesNotFire() {
		assertFalse(fires("<paths></paths>"),
				"an empty <paths> wrapper with no path elements must NOT fire");
	}
}
