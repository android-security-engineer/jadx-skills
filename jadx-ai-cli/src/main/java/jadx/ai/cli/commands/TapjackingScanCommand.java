package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Scans for tapjacking / overlay and screen-capture exposure — MASVS MSTG-PLATFORM-9. Native: reads
 * jadx's parsed model, no external tool.
 *
 * <p>Tapjacking is a UI-redress attack: a malicious app floats a transparent overlay over a victim
 * activity so the user's taps land on the victim. The defences are {@code FLAG_SECURE} (also blocks
 * screenshots/recording) and per-view {@code setFilterTouchesWhenObscured(true)} /
 * {@code FLAG_WINDOW_IS_OBSCURED} handling. This scanner surfaces both sides:
 * <ul>
 *   <li><b>overlay_window</b> (medium) — the app itself draws system overlays
 *       ({@code TYPE_APPLICATION_OVERLAY}, {@code TYPE_SYSTEM_ALERT_WINDOW}, {@code canDrawOverlays}):
 *       an overlay/phishing capability worth review.</li>
 *   <li><b>screen_capture</b> (low) — {@code MediaProjection}/{@code createScreenCaptureIntent}: the
 *       app can record the screen.</li>
 *   <li><b>touch_obscure_protection</b> (info) — {@code setFilterTouchesWhenObscured(true)} /
 *       {@code filterTouchesWhenObscured}: a tapjacking defence is present (good).</li>
 *   <li><b>flag_secure</b> (info) — {@code FLAG_SECURE}: anti-screenshot / anti-overlay-capture
 *       defence present (good).</li>
 * </ul>
 *
 * <p>Because a defence's <em>absence</em> is the real risk and absence can't be pinned to a line,
 * the boolean summary {@code hasTouchObscureProtection}/{@code usesFlagSecure} is the headline: an
 * app that draws sensitive UI but sets neither is the tapjacking-exposed case.
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, usesOverlays,
 * hasTouchObscureProtection, usesFlagSecure, truncated}}.
 */
@Command(name = "tapjacking-scan",
		description = "Scan for tapjacking/overlay exposure (MASVS MSTG-PLATFORM-9): overlay windows, screen capture, and presence of FLAG_SECURE / filterTouchesWhenObscured defences")
public class TapjackingScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	private static final class Rule {
		final Pattern pattern;
		final String kind;
		final String severity;
		final String detail;

		Rule(Pattern pattern, String kind, String severity, String detail) {
			this.pattern = pattern;
			this.kind = kind;
			this.severity = severity;
			this.detail = detail;
		}
	}

	private static final List<Rule> RULES = List.of(
			new Rule(Pattern.compile(
					// Overlay window types. TYPE_APPLICATION_OVERLAY=2038, TYPE_SYSTEM_ALERT=2003,
					// TYPE_SYSTEM_OVERLAY=2006, TYPE_SYSTEM_ERROR=2010, TYPE_PHONE=2002 — all `static final
					// int` constants, folded to literals by javac/d8, so jadx emits `params.type = 2038`
					// and the identifiers NEVER appear. The old identifier-only arms were dead code. The
					// literal arm matches the common `.type = <overlayInt>` assignment form; the identifier
					// arms remain for source-form code. canDrawOverlays() (runtime check) and the
					// SYSTEM_ALERT_WINDOW permission-name string stay (the latter appears as a literal arg
					// to requestPermission / <uses-permission> checks in code).
					"\\.type\\s*=\\s*(?:2038|2003|2006|2010|2002|2008|2009)\\b"
					+ "|TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|TYPE_SYSTEM_OVERLAY|TYPE_SYSTEM_ERROR|TYPE_PHONE\\b"
					+ "|canDrawOverlays\\s*\\(|SYSTEM_ALERT_WINDOW"),
					"overlay_window", "medium",
					"Draws a system overlay window — overlay/tapjacking/phishing capability; ensure obscured-touch handling and that it is not abusable"),
			new Rule(Pattern.compile(
					"MediaProjection|createScreenCaptureIntent\\s*\\(|registerScreenCaptureCallback\\s*\\(|VirtualDisplay"),
					"screen_capture", "low",
					"Screen-capture/recording capability (MediaProjection) — verify the recorded content and user consent"),
			new Rule(Pattern.compile(
					"setFilterTouchesWhenObscured\\s*\\(|filterTouchesWhenObscured|FLAG_WINDOW_IS_OBSCURED|onFilterTouchEventForSecurity\\s*\\("),
					"touch_obscure_protection", "info",
					"Tapjacking defence present: obscured-touch filtering"),
			new Rule(Pattern.compile(
					// FLAG_SECURE = 8192 = 0x2000, a `static final int` constant folded to the literal;
					// jadx emits `setFlags(8192, 8192)` and the identifier usually does NOT appear. The old
					// identifier-only arm was dead code on real decompiled output, so the
					// anti-screenshot defence inventory never fired. The literal arm matches the
					// setFlags/addFlags application; the identifier arm remains for source-form code.
					"setFlags\\s*\\([^)]*\\b8192\\b|addFlags\\s*\\(\\s*\\b8192\\b|FLAG_SECURE"),
					"flag_secure", "info",
					"Anti-screenshot / anti-overlay-capture defence present: WindowManager FLAG_SECURE"));

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
		boolean usesOverlays = false;
		boolean hasTouchObscureProtection = false;
		boolean usesFlagSecure = false;

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
			if (code == null || code.isEmpty()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;
				for (Rule r : RULES) {
					if (r.pattern.matcher(line).find()) {
						findings.add(finding(fullName, ln, r.kind, r.severity, r.detail));
						switch (r.kind) {
							case "overlay_window":
								usesOverlays = true;
								break;
							case "touch_obscure_protection":
								hasTouchObscureProtection = true;
								break;
							case "flag_secure":
								usesFlagSecure = true;
								break;
							default:
								break;
						}
						break; // one finding per line
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("usesOverlays", usesOverlays);
		data.put("hasTouchObscureProtection", hasTouchObscureProtection);
		data.put("usesFlagSecure", usesFlagSecure);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String cls, int line, String kind, String severity, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("kind", kind);
		f.put("severity", severity);
		f.put("className", cls);
		f.put("lineNumber", line);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "tapjacking-scan";
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
