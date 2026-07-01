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

/**
 * Analyzes Flutter/Dart APK structure by scanning for Flutter engine signatures,
 * Dart snapshot files, and Flutter-specific classes. Absorbs the design from
 * {@code blutter} (which extracts Dart info from libapp.so and analyzes the
 * Dart VM snapshot) and {@code reflutter} (which patches the Flutter engine
 * for runtime instrumentation). This native implementation focuses on the
 * static analysis layer: detecting Flutter engine presence, identifying
 * snapshot files, and extracting Dart/Flutter identifiers from the Java shell.
 */
@Command(name = "flutter-analysis", description = "Analyze Flutter/Dart APK structure and detect engine signatures")
public class FlutterAnalysisCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum findings per category", defaultValue = "200")
	protected int limit = 200;

	/** Dart snapshot magic numbers. */
	private static final int SNAPSHOT_MAGIC = 0x5D;  // Dart snapshot magic byte
	private static final String KERNEL_BLOB_MAGIC = "dart";

	/** Flutter version pattern found in libflutter.so strings. */
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

		// Scan resources for Flutter artifacts
		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name == null) continue;
			String norm = name.replace('\\', '/');

			// Check for Flutter engine .so
			if (norm.contains("libflutter.so")) {
				hasLibFlutter = true;
				flutterAssets.add(norm);
			}
			if (norm.contains("libapp.so")) {
				hasLibApp = true;
				flutterAssets.add(norm);
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
						String code = cls.getCode();
						if (code != null) {
							Matcher vm = FLUTTER_VERSION.matcher(code);
							if (vm.find()) {
								engineInfo = "Flutter " + vm.group(1);
							}
							Matcher dm = DART_VERSION.matcher(code);
							if (dm.find() && engineInfo == null) {
								engineInfo = "Dart " + dm.group(1);
							}
						}
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
			if (!snapshotFiles.isEmpty()) {
				notes.add("Dart snapshot files found — can be analyzed with Dart VM snapshot parser");
			}
			data.put("notes", notes);
		}

		return JsonOutput.ok(data);
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
