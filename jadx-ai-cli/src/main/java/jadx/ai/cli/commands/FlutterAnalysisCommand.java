package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;
import jadx.api.ResourcesLoader;

/**
 * Analyzes Flutter/Dart APK structure by scanning for Flutter engine signatures,
 * Dart snapshot files, and Flutter-specific classes. Absorbs the design from
 * {@code blutter} (which extracts Dart info from libapp.so and analyzes the
 * Dart VM snapshot) and {@code reflutter} (which patches the Flutter engine
 * for runtime instrumentation). This native implementation focuses on the
 * static analysis layer: detecting Flutter engine presence, reading the Dart/Flutter
 * version stamp embedded in {@code libapp.so}/{@code libflutter.so} (raw bytes via
 * {@code decodeStream}, blutter-style), identifying snapshot files, and extracting
 * Dart/Flutter identifiers from the Java shell.
 */
@Command(name = "flutter-analysis", description = "Analyze Flutter/Dart APK structure and detect engine signatures")
public class FlutterAnalysisCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum findings per category", defaultValue = "200")
	protected int limit = 200;

	/** Dart snapshot magic numbers. */
	private static final int SNAPSHOT_MAGIC = 0x5D;  // Dart snapshot magic byte
	private static final String KERNEL_BLOB_MAGIC = "dart";

	/** Cap bytes read per .so so a huge libapp.so can't exhaust memory (32 MiB — the Dart version
	 *  stamp lives in the VM-snapshot metadata near the start). */
	private static final long MAX_SO_BYTES = 33554432L;

	/**
	 * The Dart/Flutter release stamp embedded in {@code libapp.so}/{@code libflutter.so}, e.g.
	 * {@code 3.5.4 (stable) (Wed Oct 16 ...) on "android_arm64"}. The {@code (channel) (} shape is a
	 * strong, low-false-positive anchor — far more reliable than grepping a version out of Java code.
	 */
	private static final Pattern DART_SNAPSHOT_VERSION = Pattern.compile(
			"(\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.\\-]+)?)\\s+\\((stable|beta|dev|main|be)\\)\\s+\\(");
	/** Fallback: a version pattern on a line that actually mentions "version" (cuts Java-code noise). */
	private static final Pattern FLUTTER_VERSION = Pattern.compile("(\\d+\\.\\d+\\.\\d+(?:-[\\w.]+)?)");
	private static final Pattern DART_VERSION = Pattern.compile("dart[:\\s]+(\\d+\\.\\d+\\.\\d+)");

	/** Dart class/function name patterns (from blutter's analysis approach). */
	private static final Pattern DART_IDENTIFIER = Pattern.compile("([A-Z][A-Za-z0-9_]+(?:Widget|State|Provider|Repository|Service|Controller|Model|Bloc|Cubit|Handler|Helper|Manager|Client|Adapter|Factory|Builder|Delegate|DataSource|UseCase|Interceptor|Converter|Validator|Parser|Serializer|Repository))\\b");

	/** Flutter framework patterns in Java code. */
	private static final Pattern FLUTTER_JAVA = Pattern.compile("io\\.flutter\\.(app|embedding|view|plugin|engine)");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<String> flutterAssets = new ArrayList<>();
		List<String> snapshotFiles = new ArrayList<>();
		boolean hasLibFlutter = false;
		boolean hasLibApp = false;
		String engineInfo = null;
		ResourceFile libAppRes = null;
		ResourceFile libFlutterRes = null;

		// Scan resources for Flutter artifacts
		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name == null) continue;
			String norm = name.replace('\\', '/');

			// Check for Flutter engine .so
			if (norm.contains("libflutter.so")) {
				hasLibFlutter = true;
				flutterAssets.add(norm);
				if (res.getType() == ResourceType.LIB) {
					libFlutterRes = res;
				}
			}
			if (norm.contains("libapp.so")) {
				hasLibApp = true;
				flutterAssets.add(norm);
				if (res.getType() == ResourceType.LIB) {
					libAppRes = res;
				}
			}

			// Check for Dart snapshot files
			if (norm.contains("isolate_snapshot_data") || norm.contains("isolate_snapshot_instr")
					|| norm.contains("vm_snapshot_data") || norm.contains("vm_snapshot_instr")
					|| norm.contains("kernel_blob.bin")) {
				snapshotFiles.add(norm);
			}

			// Check for flutter_assets directory
			if (norm.contains("flutter_assets/")) {
				flutterAssets.add(norm);
			}

			// Check for AssetManifest
			if (norm.contains("AssetManifest.json") || norm.contains("AssetManifest.bin.json")) {
				flutterAssets.add(norm);
			}
		}

		// Ground truth: read the engine .so's embedded Dart/Flutter version stamp (blutter's approach),
		// reading raw bytes via decodeStream — NOT loadContent().getText(), which would corrupt the
		// binary. libapp.so carries the snapshot version; libflutter.so is the fallback source.
		boolean snapshotInLibApp = false;
		String versionSource = null;
		ResourceFile[] engineOrder = { libAppRes, libFlutterRes };
		for (ResourceFile so : engineOrder) {
			if (so == null) {
				continue;
			}
			String strings = readSoStrings(so);
			if (strings == null) {
				continue;
			}
			if (so == libAppRes && (strings.contains("Dart") || DART_SNAPSHOT_VERSION.matcher(strings).find())) {
				// A release build embeds the Dart snapshot inside libapp.so (no separate *_snapshot_* files).
				snapshotInLibApp = true;
			}
			Matcher vm = DART_SNAPSHOT_VERSION.matcher(strings);
			if (vm.find()) {
				engineInfo = "Dart " + vm.group(1) + " (" + vm.group(2) + ")";
				versionSource = so.getOriginalName();
				break;
			}
		}

		// Scan Java code for Flutter embedding
		List<Map<String, Object>> dartIdentifiers = new ArrayList<>();
		boolean hasFlutterJava = false;
		for (JavaClass cls : decompiler.getClasses()) {
			String fullName = cls.getFullName();
			if (fullName.startsWith("io.flutter.")) {
				hasFlutterJava = true;
				// Try to extract version from FlutterJNI or similar
				if (engineInfo == null) {
					try {
						engineInfo = versionFromJava(cls.getCode());
					} catch (Exception e) {
						// Skip
					}
				}
			}
			// Look for Dart-to-Flutter patterns in app code
			if (!fullName.startsWith("io.flutter.") && !fullName.startsWith("android.")) {
				try {
					String code = cls.getCode();
					if (code != null) {
						Matcher m = DART_IDENTIFIER.matcher(code);
						while (m.find() && dartIdentifiers.size() < limit) {
							Map<String, Object> id = new LinkedHashMap<>();
							id.put("name", m.group(1));
							id.put("kind", "dart-widget-or-class");
							id.put("className", fullName);
							dartIdentifiers.add(id);
						}
					}
				} catch (Exception e) {
					// Skip
				}
			}
		}

		boolean isFlutter = hasLibFlutter || hasLibApp || hasFlutterJava;

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("isFlutter", isFlutter);
		data.put("hasLibFlutter", hasLibFlutter);
		data.put("hasLibApp", hasLibApp);
		data.put("hasFlutterJava", hasFlutterJava);
		data.put("engineInfo", engineInfo);
		if (versionSource != null) {
			data.put("engineVersionSource", versionSource); // which .so the version came from (ground truth)
		}
		data.put("snapshotEmbeddedInLibApp", snapshotInLibApp);
		data.put("snapshotFiles", snapshotFiles);
		data.put("flutterAssets", flutterAssets);
		data.put("dartIdentifiers", dartIdentifiers);
		data.put("dartIdentifierCount", dartIdentifiers.size());

		if (isFlutter) {
			List<String> notes = new ArrayList<>();
			notes.add("Flutter app detected — Java/Kotlin layer is a thin shell; real logic is in Dart");
			if (hasLibApp) {
				notes.add("libapp.so contains compiled Dart code — use blutter/reFlutter for deeper analysis");
			}
			if (snapshotInLibApp) {
				notes.add("Dart snapshot is embedded in libapp.so (AOT release build) — no separate *_snapshot_* files");
			}
			if (!snapshotFiles.isEmpty()) {
				notes.add("Dart snapshot files found — can be analyzed with Dart VM snapshot parser");
			}
			data.put("notes", notes);
		}

		return JsonOutput.ok(data);
	}

	/** Read a .so's raw bytes (capped) via the binary-safe decodeStream path and return its ASCII strings. */
	private static String readSoStrings(ResourceFile so) {
		try {
			byte[] data = ResourcesLoader.decodeStream(so,
					(size, is) -> is.readNBytes((int) Math.min(MAX_SO_BYTES, Integer.MAX_VALUE)));
			if (data == null || data.length < 16) {
				return null;
			}
			return asciiStrings(data, 6);
		} catch (Exception e) {
			return null;
		}
	}

	/** Extract printable-ASCII runs of at least {@code minLen} chars, newline-separated. */
	static String asciiStrings(byte[] data, int minLen) {
		StringBuilder sb = new StringBuilder();
		StringBuilder cur = new StringBuilder();
		for (byte b : data) {
			if (b >= 32 && b < 127) {
				cur.append((char) b);
			} else {
				if (cur.length() >= minLen) {
					sb.append(cur).append('\n');
				}
				cur.setLength(0);
			}
		}
		if (cur.length() >= minLen) {
			sb.append(cur);
		}
		return sb.toString();
	}

	/**
	 * Last-resort version guess from decompiled Java: only a line that actually mentions "version"
	 * is trusted, so a stray {@code 1.2.3} constant in a Flutter shell class is not misreported.
	 */
	static String versionFromJava(String code) {
		if (code == null) {
			return null;
		}
		for (String line : code.split("\n", -1)) {
			if (line.toLowerCase(java.util.Locale.ROOT).contains("version")) {
				Matcher dm = DART_VERSION.matcher(line);
				if (dm.find()) {
					return "Dart " + dm.group(1);
				}
				Matcher vm = FLUTTER_VERSION.matcher(line);
				if (vm.find()) {
					return "Flutter " + vm.group(1);
				}
			}
		}
		return null;
	}

	@Override
	protected String getDaemonCommandName() {
		return "flutter-analysis";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("limit", limit);
		return args;
	}
}
