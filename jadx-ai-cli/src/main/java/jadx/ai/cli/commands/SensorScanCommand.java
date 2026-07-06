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

	// Sensor type constants → human name, for the sensorTypes inventory. Sensor.TYPE_* are
	// `static final int` constants, folded to their integer literals by javac/d8, so jadx decompiles
	// `getDefaultSensor(Sensor.TYPE_ACCELEROMETER)` as `getDefaultSensor(1)` — the identifier NEVER
	// appears. The FIRST column is therefore the integer literal value (matched in a
	// `getDefaultSensor(<value>)` call context so a bare number elsewhere does not false-positive);
	// the SECOND is the human name; the THIRD is the short tag. Package-private for testing.
	static final String[][] SENSOR_TYPES = {
			{ "1", "accelerometer", "accel" },        // TYPE_ACCELEROMETER
			{ "4", "gyroscope", "gyro" },             // TYPE_GYROSCOPE
			{ "2", "magnetometer", "mag" },           // TYPE_MAGNETIC_FIELD
			{ "8", "proximity", "prox" },             // TYPE_PROXIMITY
			{ "5", "light", "ambient light" },        // TYPE_LIGHT
			{ "6", "barometer", "pressure" },         // TYPE_PRESSURE
			{ "11", "rotation vector", "rotation" },  // TYPE_ROTATION_VECTOR
			{ "10", "linear acceleration", "linear accel" }, // TYPE_LINEAR_ACCELERATION
			{ "9", "gravity", "grav" },               // TYPE_GRAVITY
			{ "3", "orientation", "orient" },         // TYPE_ORIENTATION (deprecated)
	};

	/** A {@code getDefaultSensor(<typeInt>)} call — the decompiled form of {@code getDefaultSensor(Sensor.TYPE_*)}. Package-private for testing. */
	static final Pattern SENSOR_TYPE_CALL = Pattern.compile("getDefaultSensor\\s*\\(\\s*(\\d+)\\b");

	private static final List<Rule> RULES = List.of(
			new Rule("registerListener\\s*\\(",
					"sensor_register_listener", "medium",
					"SensorManager.registerListener — subscribes to sensor events; long-lived listeners can infer taps (accelerometer), orientation, and context without an obvious permission on many devices"),
			// Motion sensors: TYPE_ACCELEROMETER(1)/TYPE_GYROSCOPE(4)/TYPE_LINEAR_ACCELERATION(10)/TYPE_GRAVITY(9),
			// matched at the getDefaultSensor(<int>) call site (the identifier is folded to the literal).
			new Rule("getDefaultSensor\\s*\\(\\s*(?:1|4|10|9)\\b|TYPE_ACCELEROMETER|TYPE_GYROSCOPE|TYPE_LINEAR_ACCELERATION|TYPE_GRAVITY",
					"sensor_motion", "medium",
					"Motion sensor (accelerometer/gyroscope/linear acceleration/gravity) — the keystroke-inference and gesture side-channel source"),
			// Orientation: TYPE_MAGNETIC_FIELD(2)/TYPE_ORIENTATION(3)/TYPE_ROTATION_VECTOR(11).
			new Rule("getDefaultSensor\\s*\\(\\s*(?:2|3|11)\\b|TYPE_MAGNETIC_FIELD|TYPE_ORIENTATION|TYPE_ROTATION_VECTOR",
					"sensor_orientation", "low",
					"Orientation/magnetic sensor — can infer heading and rough location context"),
			// Proximity(8)/light(5).
			new Rule("getDefaultSensor\\s*\\(\\s*(?:8|5)\\b|TYPE_PROXIMITY|TYPE_LIGHT",
					"sensor_proximity_light", "low",
					"Proximity/ambient-light sensor — can infer screen-on state and phone-to-ear behaviour"),
			new Rule("SensorManager\\.getRotationMatrix|getOrientation\\s*\\(",
					"sensor_rotation_calc", "low",
					"Computes device rotation/orientation from sensor data — corroborates an orientation-aware (context-inference) flow"),
			// SENSOR_DELAY_* (FASTEST=0/GAME=1/UI=2/NORMAL=3) are `static final int` folded to literals;
			// matching a bare 0/1/2/3 in registerListener would false-positive heavily (those are common
			// arg values), so this rule relies on the setDelay/setReportingMode method-name arms and the
			// identifier arms (source-form). The identifier arms are dead on decompiled output but the
			// method-name arms keep the rule alive; documented limitation.
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

			// Inventory sensor types referenced at class level. The identifier `Sensor.TYPE_*` is
			// folded to its integer literal, so we capture the int arg of every getDefaultSensor(<int>)
			// call and map it back to the human name via SENSOR_TYPES.
			java.util.regex.Matcher tm = SENSOR_TYPE_CALL.matcher(code);
			while (tm.find()) {
				String typeVal = tm.group(1);
				for (String[] st : SENSOR_TYPES) {
					if (st[0].equals(typeVal) && !sensorTypes.contains(st[1])) {
						sensorTypes.add(st[1]);
					}
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
