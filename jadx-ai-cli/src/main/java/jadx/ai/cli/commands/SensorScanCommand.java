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
 * Scans for sensor side-channels — the use of device sensors (accelerometer, gyroscope,
 * magnetometer, proximity, light, etc.) beyond their obvious purpose. High-rate or
 * long-running sensor listeners can infer keystrokes (motion of taps), screen content
 * (orientation + proximity), and location context (magnetic heading), and on some devices
 * sensors are accessible without a permission. Reports {@code SensorManager.registerListener},
 * the sensor types requested, and the high-sampling-rate / always-on signals. MASVS
 * MSTG-STORAGE-12 / MSTG-PRIVACY. Distinct from {@code privacy-scan} (which covers sensors as
 * one PII category) — this is the dedicated, sensor-flavoured deep dive with rate/always-on
 * triage.
 *
 * <p>Returns {@code {findings, count, highSeverityCount, usesSensors, sensorTypes,
 * hasHighRate, hasAlwaysOn}}.
 */
@Command(name = "sensor-scan",
		description = "Scan for sensor side-channels (SensorManager.registerListener, accelerometer/gyro/proximity, high sampling rate)")
public class SensorScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern SENSOR_MARKER = Pattern.compile(
			"SensorManager|SensorEventListener|Sensor\\.|getDefaultInstance|registerListener|android\\.hardware\\.Sensor");

	private static final class Rule {
		final Pattern pattern;
		final String kind;
		final String severity;
		final String detail;

		Rule(String regex, String kind, String severity, String detail) {
			this.pattern = Pattern.compile(regex);
			this.kind = kind;
			this.severity = severity;
			this.detail = detail;
		}
	}

	// Sensor type constants (the integer) → human name, for the sensorTypes inventory.
	private static final String[][] SENSOR_TYPES = {
			{ "TYPE_ACCELEROMETER", "accelerometer", "accel" },
			{ "TYPE_GYROSCOPE", "gyroscope", "gyro" },
			{ "TYPE_MAGNETIC_FIELD", "magnetometer", "mag" },
			{ "TYPE_PROXIMITY", "proximity", "prox" },
			{ "TYPE_LIGHT", "light", "ambient light" },
			{ "TYPE_PRESSURE", "barometer", "pressure" },
			{ "TYPE_ROTATION_VECTOR", "rotation vector", "rotation" },
			{ "TYPE_LINEAR_ACCELERATION", "linear acceleration", "linear accel" },
			{ "TYPE_GRAVITY", "gravity", "grav" },
			{ "TYPE_ORIENTATION", "orientation", "orient" },
	};

	private static final List<Rule> RULES = List.of(
			new Rule("registerListener\\s*\\(",
					"sensor_register_listener", "medium",
					"SensorManager.registerListener — subscribes to sensor events; long-lived listeners can infer taps (accelerometer), orientation, and context without an obvious permission on many devices"),
			new Rule("TYPE_ACCELEROMETER|TYPE_GYROSCOPE|TYPE_LINEAR_ACCELERATION|TYPE_GRAVITY",
					"sensor_motion", "medium",
					"Motion sensor (accelerometer/gyroscope/linear acceleration/gravity) — the keystroke-inference and gesture side-channel source"),
			new Rule("TYPE_MAGNETIC_FIELD|TYPE_ORIENTATION|TYPE_ROTATION_VECTOR",
					"sensor_orientation", "low",
					"Orientation/magnetic sensor — can infer heading and rough location context"),
			new Rule("TYPE_PROXIMITY|TYPE_LIGHT",
					"sensor_proximity_light", "low",
					"Proximity/ambient-light sensor — can infer screen-on state and phone-to-ear behaviour"),
			new Rule("SensorManager\\.getRotationMatrix|getOrientation\\s*\\(",
					"sensor_rotation_calc", "low",
					"Computes device rotation/orientation from sensor data — corroborates an orientation-aware (context-inference) flow"),
			new Rule("PERIODIC|FASTEST|GAME|UI|setDelay|setReportingMode",
					"sensor_rate", "high",
					"High reporting rate / fast delay (FASTEST/GAME/PERIODIC) — sampling fast enough for keystroke or motion inference; review whether the rate is justified"));

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
		boolean usesSensors = false;
		List<String> sensorTypes = new ArrayList<>();
		boolean hasHighRate = false;
		boolean hasAlwaysOn = false;

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
			if (code == null || code.isEmpty() || !SENSOR_MARKER.matcher(code).find()) {
				continue;
			}
			usesSensors = true;

			// Inventory sensor types referenced at class level.
			for (String[] st : SENSOR_TYPES) {
				if (code.contains(st[0]) && !sensorTypes.contains(st[1])) {
					sensorTypes.add(st[1]);
				}
			}
			// Always-on heuristic: a sensor listener registered in onResume/onCreate without
			// a matching unregister in onPause/onStop — cheap text signal.
			if (code.contains("registerListener") && !code.contains("unregisterListener")) {
				hasAlwaysOn = true;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				for (Rule r : RULES) {
					if (!r.pattern.matcher(line).find()) {
						continue;
					}
					findings.add(finding(fullName, i + 1, r.kind, r.severity, r.detail));
					if ("high".equals(r.severity)) {
						highSeverityCount++;
						hasHighRate = true;
					}
					break;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("usesSensors", usesSensors);
		data.put("sensorTypes", sensorTypes);
		data.put("hasHighRate", hasHighRate);
		data.put("hasAlwaysOn", hasAlwaysOn);
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
		return "sensor-scan";
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
