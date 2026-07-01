package jadx.ai.cli.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;

/**
 * Shared helpers for reading and parsing {@code AndroidManifest.xml} from a decompiled APK.
 * Extracted from NavigateCommand so multiple commands (navigation, permission analysis, ...)
 * use a single source of truth.
 */
public final class ManifestUtil {

	private ManifestUtil() {
	}

	/** Load the decoded {@code AndroidManifest.xml} text, or {@code null} if not present. */
	public static String loadManifestText(JadxDecompiler decompiler) {
		return loadResourceText(decompiler, "AndroidManifest.xml");
	}

	/**
	 * Load the decoded text of the first resource whose original name contains {@code nameContains},
	 * or {@code null} if none matches. Used to read config XML (network_security_config, etc.).
	 */
	public static String loadResourceText(JadxDecompiler decompiler, String nameContains) {
		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name != null && name.contains(nameContains)) {
				var container = res.loadContent();
				if (container != null) {
					return container.getText().toString();
				}
			}
		}
		return null;
	}

	/** Extract all declared {@code uses-permission} names from manifest text. */
	public static List<String> extractPermissions(String manifest) {
		return extractAll(manifest, "<uses-permission[^>]*android:name=\"([^\"]+)\"");
	}

	/** Return the first capture group of {@code regex} (DOTALL) in {@code text}, or {@code null}. */
	public static String extractFirst(String text, String regex) {
		Pattern p = Pattern.compile(regex, Pattern.DOTALL);
		Matcher m = p.matcher(text);
		return m.find() && m.groupCount() >= 1 ? m.group(1) : null;
	}

	/** Return all first-group matches of {@code regex} (DOTALL) in {@code text}. */
	public static List<String> extractAll(String text, String regex) {
		List<String> out = new ArrayList<>();
		if (text == null) {
			return out;
		}
		Pattern p = Pattern.compile(regex, Pattern.DOTALL);
		Matcher m = p.matcher(text);
		while (m.find()) {
			if (m.groupCount() >= 1) {
				out.add(m.group(1));
			}
		}
		return out;
	}
}
