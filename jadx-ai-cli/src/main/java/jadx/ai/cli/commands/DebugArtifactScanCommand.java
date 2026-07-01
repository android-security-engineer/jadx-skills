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
 * Debug-artifact / instrumentation-residue scanner — MASVS MSTG-CODE-4 / MSTG-RESILIENCE-1.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Distinct from {@code logging-scan} (flags Log/Logger API calls) and
 * {@code tamper-detection-scan} (inventories anti-tamper / anti-hook defences). This scanner
 * detects <b>third-party debug/instrumentation libraries</b> and <b>debug-conditional branches</b>
 * that are left in a release build — a clear signal that the app was not properly stripped for
 * production, and that runtime inspection / data exfiltration via those libraries is possible.
 *
 * <p>Categories (first-match-wins per line):
 * <ul>
 *   <li>{@code debug_lib} — known debug/instrumentation libraries present in the classpath
 *       (Stetho, Flipper, LeakCanary, Chucker, Chuck, HTTP Inspector, Google BinderSpy,
 *        Android Debug Database, Lynx, Segun-Franko debugger)</li>
 *   <li>{@code debug_branch} — {@code BuildConfig.DEBUG} or {@code Build.BETA} runtime branches
 *       that ship in the release APK</li>
 *   <li>{@code strict_mode} — {@code StrictMode} penalty/enable calls (development-only guard)</li>
 *   <li>{@code profiler} — profiling / benchmark instrumentation (Debug.startMethodTracing,
 *       Debug.startMethodTracingSampling, Debug.startMethodTracingDdms)</li>
 * </ul>
 *
 * <p>Inventory shape (no severity — presence of a debug lib in a release build is always worth
 * reporting; the impact depends on context). The boolean flags {@code hasDebugLibs} /
 * {@code hasDebugBranches} / {@code hasStrictMode} / {@code hasProfiler} let a review
 * quickly filter.
 *
 * Returns {@code {findings:[{category,className,lineNumber,detail}], count, hasDebugLibs,
 * hasDebugBranches, hasStrictMode, hasProfiler, debugLibs, truncated}}.
 */
@Command(name = "debug-artifact-scan",
		description = "Detect debug/instrumentation artifacts left in a release build (MASVS MSTG-CODE-4 / MSTG-RESILIENCE-1): Stetho, Flipper, LeakCanary, Chucker, HTTP Inspector, Android Debug Database, StrictMode, BuildConfig.DEBUG branches, method-tracing profiler. Distinct from logging-scan (Log API calls) and tamper-detection-scan (anti-hook defences)")
public class DebugArtifactScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Gate: only scan a class that touches debug/instrumentation artifacts. */
	private static final Pattern DEBUG_MARKER = Pattern.compile(
			"Stetho|Flipper|LeakCanary|Chucker|Chuck|HttpInspector|BinderSpy|DebugDB|LynxDebugger|"
					+ "SegunFranko|BuildConfig\\.DEBUG|Build\\.BETA|StrictMode|startMethodTracing");

	// --- debug_lib rules (class-level: once per class per library) ---

	private static final Pattern[] DEBUG_LIB_PATTERNS = {
		// Stetho — Facebook's Chrome DevTools bridge for Android
		Pattern.compile("com\\.facebook\\.stetho|Stetho\\."),
		// Flipper — Facebook's extensible debug platform
		Pattern.compile("com\\.facebook\\.flipper|FlipperClient|FlipperPlugin|ReactNativeFlipper"),
		// LeakCanary — Square's memory-leak detector
		Pattern.compile("leakcanary|LeakCanary"),
		// Chucker — HTTP inspector (modern Chuck fork)
		Pattern.compile("com\\. chuckerteam\\.chucker|Chucker"),
		// Chuck — older HTTP inspector (deprecated, predecessor of Chucker)
		Pattern.compile("com\\.readystatesoftware\\.chuck|ChuckInterceptor"),
		// HTTP Inspector — another network debug proxy
		Pattern.compile("HttpInspector|httpinspector"),
		// Google BinderSpy
		Pattern.compile("BinderSpy"),
		// Android Debug Database (amitshekhar)
		Pattern.compile("com\\.amitshekhar\\.utils\\.debug|DebugDB"),
		// Lynx debugger
		Pattern.compile("com\\.github\\.piasy\\.lynx|LynxDebugger"),
		// Segun-Franko debugger
		Pattern.compile("SegunFranko|segunfranko"),
	};

	private static final String[] DEBUG_LIB_NAMES = {
		"stetho", "flipper", "leakcanary", "chucker", "chuck",
		"http_inspector", "binderspy", "debug_db", "lynx", "segun_franko",
	};

	private static final String[] DEBUG_LIB_DETAILS = {
		"Facebook Stetho — Chrome DevTools bridge for runtime inspection (network, DB, view hierarchy)",
		"Facebook Flipper — extensible debug platform (network, layout, DB, logs); should not ship in release",
		"LeakCanary — memory-leak detection library; development-only, should be stripped from release builds",
		"Chucker — HTTP traffic inspector; displays network requests in-app, should not ship in release",
		"Chuck — HTTP traffic inspector (deprecated predecessor of Chucker); should not ship in release",
		"HTTP Inspector — network debug proxy; should not ship in release",
		"BinderSpy — debug tool for observing Binder IPC; should not ship in release",
		"Android Debug Database — in-app DB viewer; exposes database contents, should not ship in release",
		"Lynx — debug log viewer; should not ship in release",
		"Segun-Franko debugger; should not ship in release",
	};

	// --- debug_branch rules ---
	private static final Pattern BUILD_CONFIG_DEBUG = Pattern.compile("BuildConfig\\.DEBUG");
	private static final Pattern BUILD_BETA = Pattern.compile("Build\\.BETA");

	// --- strict_mode rules ---
	private static final Pattern STRICT_MODE_ENABLE = Pattern.compile(
			"StrictMode\\.(enableDefaults|setThreadPolicy|setVmPolicy|allowThreadDiskReads|allowThreadDiskWrites|allowCustomSlowCalls|penaltyLog|penaltyDeath|penaltyDialog|penaltyFlashScreen|penaltyDropBox)");

	// --- profiler rules ---
	private static final Pattern METHOD_TRACING = Pattern.compile(
			"Debug\\.startMethodTracing[^S]|Debug\\.startMethodTracingSampling|Debug\\.startMethodTracingDdms");

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
		boolean hasDebugLibs = false;
		boolean hasDebugBranches = false;
		boolean hasStrictMode = false;
		boolean hasProfiler = false;
		TreeSet<String> debugLibs = new TreeSet<>();

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
			if (code == null || code.isEmpty() || !DEBUG_MARKER.matcher(code).find()) {
				continue;
			}

			// Track which debug libs we've already reported for this class (once per class per lib).
			boolean[] reportedLib = new boolean[DEBUG_LIB_PATTERNS.length];
			boolean reportedDebugBranch = false;
			boolean reportedStrictMode = false;
			boolean reportedProfiler = false;

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				// debug_lib: check each known library pattern
				for (int j = 0; j < DEBUG_LIB_PATTERNS.length; j++) {
					if (!reportedLib[j] && DEBUG_LIB_PATTERNS[j].matcher(line).find()) {
						hasDebugLibs = true;
						debugLibs.add(DEBUG_LIB_NAMES[j]);
						findings.add(finding("debug_lib", fullName, i + 1,
								DEBUG_LIB_NAMES[j] + ": " + DEBUG_LIB_DETAILS[j]));
						reportedLib[j] = true;
						break; // first-match-wins per line (a line can only match one lib)
					}
				}

				// debug_branch: BuildConfig.DEBUG or Build.BETA
				if (!reportedDebugBranch && (BUILD_CONFIG_DEBUG.matcher(line).find() || BUILD_BETA.matcher(line).find())) {
					hasDebugBranches = true;
					String which = BUILD_CONFIG_DEBUG.matcher(line).find() ? "BuildConfig.DEBUG" : "Build.BETA";
					findings.add(finding("debug_branch", fullName, i + 1,
							which + " runtime branch shipped in release build — debug code paths reachable"));
					reportedDebugBranch = true;
				}

				// strict_mode
				if (!reportedStrictMode && STRICT_MODE_ENABLE.matcher(line).find()) {
					hasStrictMode = true;
					findings.add(finding("strict_mode", fullName, i + 1,
							"StrictMode enabled — development-only performance guard, should be removed for release"));
					reportedStrictMode = true;
				}

				// profiler
				if (!reportedProfiler && METHOD_TRACING.matcher(line).find()) {
					hasProfiler = true;
					findings.add(finding("profiler", fullName, i + 1,
							"Debug.startMethodTracing / startMethodTracingSampling / startMethodTracingDdms — "
									+ "method-profiling instrumentation should be removed for release"));
					reportedProfiler = true;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("hasDebugLibs", hasDebugLibs);
		data.put("hasDebugBranches", hasDebugBranches);
		data.put("hasStrictMode", hasStrictMode);
		data.put("hasProfiler", hasProfiler);
		data.put("debugLibs", new ArrayList<>(debugLibs));
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String category, String className, int line, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("category", category);
		f.put("className", className);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "debug-artifact-scan";
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
