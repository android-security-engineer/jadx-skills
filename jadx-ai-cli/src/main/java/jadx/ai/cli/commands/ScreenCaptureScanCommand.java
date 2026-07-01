package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Screen-capture / screen-recording security scanner — MASVS MSTG-PLATFORM-4.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code tapjacking-scan} (overlay-based UI hijacking) and
 * {@code tamper-detection-scan} (anti-hook / anti-tamper defences). This scanner focuses on
 * <b>screen-content leakage</b>: whether the app protects its screen from being captured
 * (screenshot / screen recording), and whether it <em>itself</em> records screens via
 * {@code MediaProjection} / {@code VirtualDisplay} (a potential spyware indicator).
 *
 * <p>Categories:
 * <ul>
 *   <li>{@code flag_secure_absent} — Activity that displays sensitive data but does not set
 *       {@code FLAG_SECURE} on its window — screenshots and screen recordings capture the content</li>
 *   <li>{@code flag_secure_set} — Activity sets {@code FLAG_SECURE} — screen-capture defence
 *       present (inventory, not a vulnerability)</li>
 *   <li>{@code media_projection} — {@code MediaProjection} / {@code createVirtualDisplay} usage —
 *       the app can record the screen; check for proper user consent and scope</li>
 *   <li>{@code screenshot_api} — {@code Screenshot} / {@code PixelCopy} / {@code takeScreenshot}
 *       usage — programmatic screen capture capability</li>
 * </ul>
 *
 * <p>Mixed shape: defence inventory (flag_secure_set) + vulnerability flags (flag_secure_absent)
 * + capability inventory (media_projection, screenshot_api).
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count,
 * highSeverityCount, hasFlagSecure, hasMediaProjection, hasScreenshotApi, truncated}}.
 */
@Command(name = "screen-capture-scan",
		description = "Detect screen-capture / screen-recording risks (MASVS MSTG-PLATFORM-4): FLAG_SECURE absence (screenshot exposure), FLAG_SECURE presence (defence inventory), MediaProjection/VirtualDisplay usage (screen recording capability), Screenshot/PixelCopy API usage. Distinct from tapjacking-scan and tamper-detection-scan")
public class ScreenCaptureScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	/** Gate: only scan classes touching screen-capture related APIs. */
	private static final Pattern SCREEN_MARKER = Pattern.compile(
			"FLAG_SECURE|MediaProjection|VirtualDisplay|createVirtualDisplay|Screenshot|PixelCopy|takeScreenshot|ScreenCapture");

	/**
	 * A real {@code FLAG_SECURE} application to a window — {@code setFlags(…, FLAG_SECURE)} or
	 * {@code addFlags(FLAG_SECURE)}. This (NOT the bare {@code FLAG_SECURE} literal) is what proves the
	 * defence is actually in effect; the bare literal also matches a comment or a {@code setFlags(0, …)}
	 * mask-only call. Package-private so a test can assert the absent-finding uses the real form.
	 */
	static final Pattern FLAG_SECURE_ON_WINDOW = Pattern.compile(
			"setFlags\\s*\\(.*FLAG_SECURE|addFlags\\s*\\(.*FLAG_SECURE|FLAG_SECURE.*setFlags|FLAG_SECURE.*addFlags");
	/** An Activity-class marker — only Activity windows are candidates for FLAG_SECURE absence. */
	static final Pattern ACTIVITY_MARKER = Pattern.compile(
			"extends\\s+(Activity|AppCompatActivity|FragmentActivity|BaseActivity|ActionBarActivity)"
					+ "|setContentView\\s*\\(");
	private static final Pattern MEDIA_PROJECTION = Pattern.compile(
			"MediaProjection|createVirtualDisplay|VirtualDisplay|MediaProjectionManager");
	private static final Pattern SCREENSHOT_API = Pattern.compile(
			"PixelCopy|takeScreenshot|Screenshot\\.capture|screenshot\\s*\\(");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();
		int highSeverityCount = 0;
		boolean hasFlagSecure = false;
		boolean hasMediaProjection = false;
		boolean hasScreenshotApi = false;

		for (JavaClass cls : decompiler.getClasses()) {
			if (findings.size() >= limit) {
				break;
			}
			String fullName = cls.getFullName();
			if (packageFilter != null && !fullName.startsWith(packageFilter)) {
				continue;
			}
			String code;
			try {
				code = cls.getCode();
			} catch (Exception e) {
				continue;
			}
			if (code == null || code.isEmpty() || !SCREEN_MARKER.matcher(code).find()) {
				continue;
			}

			// Class-level checks
			// hasFlagSecure uses the REAL setFlags/addFlags application, not the bare FLAG_SECURE literal —
			// a comment or a mask-only setFlags(0, ...) mentioning FLAG_SECURE must NOT count as defended.
			boolean classHasFlagSecure = FLAG_SECURE_ON_WINDOW.matcher(code).find();
			boolean classIsActivity = ACTIVITY_MARKER.matcher(code).find();
			boolean classHasMediaProjection = MEDIA_PROJECTION.matcher(code).find();
			boolean classHasScreenshotApi = SCREENSHOT_API.matcher(code).find();

			if (classHasFlagSecure) {
				hasFlagSecure = true;
			}
			if (classHasMediaProjection) {
				hasMediaProjection = true;
			}
			if (classHasScreenshotApi) {
				hasScreenshotApi = true;
			}

			// FLAG_SECURE absent on an Activity — the documented high-severity finding that was promised
			// in the class doc but never emitted. An Activity window without FLAG_SECURE is captured by
			// screenshots / screen recordings; one per class.
			if (classIsActivity && !classHasFlagSecure && findings.size() < limit) {
				findings.add(finding("flag_secure_absent", "high", fullName, 0,
						"Activity does not set FLAG_SECURE — its content is captured by screenshots and "
								+ "screen recordings (MASVS MSTG-PLATFORM-4); add getWindow().setFlags("
								+ "WindowManager.LayoutParams.FLAG_SECURE, FLAG_SECURE) for screens showing "
								+ "sensitive data"));
				highSeverityCount++;
			}

			// Per-line detection
			boolean reportedFlagSecure = false;
			boolean reportedMediaProjection = false;
			boolean reportedScreenshot = false;

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				// FLAG_SECURE set on window — defence inventory
				if (!reportedFlagSecure && FLAG_SECURE_ON_WINDOW.matcher(line).find()) {
					findings.add(finding("flag_secure_set", "info", fullName, i + 1,
							"FLAG_SECURE set on window — screen-capture defence present; "
									+ "screenshots and screen recordings will show a black canvas"));
					reportedFlagSecure = true;
					continue;
				}

				// MediaProjection / VirtualDisplay — screen recording capability
				if (!reportedMediaProjection && MEDIA_PROJECTION.matcher(line).find()) {
					findings.add(finding("media_projection", "medium", fullName, i + 1,
							"MediaProjection / VirtualDisplay usage — the app can record the device screen; "
									+ "verify proper user consent (MediaProjection requires a system permission dialog) "
									+ "and that the recording scope is limited"));
					reportedMediaProjection = true;
					continue;
				}

				// Screenshot API
				if (!reportedScreenshot && SCREENSHOT_API.matcher(line).find()) {
					findings.add(finding("screenshot_api", "info", fullName, i + 1,
							"PixelCopy / takeScreenshot / Screenshot API — programmatic screen-capture capability; "
									+ "verify this is used for legitimate purposes (e.g., in-app feedback) "
									+ "and does not silently capture other apps' content"));
					reportedScreenshot = true;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("hasFlagSecure", hasFlagSecure);
		data.put("hasMediaProjection", hasMediaProjection);
		data.put("hasScreenshotApi", hasScreenshotApi);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String kind, String severity, String className, int line, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("className", className);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "screen-capture-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
