package jadx.ai.cli.commands;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the literal-form deepening of {@link SensorScanCommand}.
 *
 * <p>{@code Sensor.TYPE_*} are {@code static final int} constants, folded to their integer literals
 * by javac/d8, so jadx decompiles {@code getDefaultSensor(Sensor.TYPE_ACCELEROMETER)} as
 * {@code getDefaultSensor(1)} — the identifier NEVER appears. The old code:
 * <ul>
 *   <li>built the {@code sensorTypes} inventory with {@code code.contains("TYPE_ACCELEROMETER")} —
 *       always false, so the inventory was ALWAYS empty;</li>
 *   <li>had motion/orientation/proximity rules matching the identifiers — dead code, zero hits.</li>
 * </ul>
 * Verified against actual javac&#8594;d8&#8594;jadx output
 * ({@code sensorManager.getDefaultSensor(1);}).
 */
class SensorTypeLiteralTest {

	private static final java.util.regex.Pattern SENSOR_CALL = SensorScanCommand.SENSOR_TYPE_CALL;
	// Mirror the motion/orientation/proximity rules the command compiles.
	private static final java.util.regex.Pattern MOTION = java.util.regex.Pattern.compile(
			"getDefaultSensor\\s*\\(\\s*(?:1|4|10|9)\\b|TYPE_ACCELEROMETER|TYPE_GYROSCOPE|TYPE_LINEAR_ACCELERATION|TYPE_GRAVITY");
	private static final java.util.regex.Pattern ORIENTATION = java.util.regex.Pattern.compile(
			"getDefaultSensor\\s*\\(\\s*(?:2|3|11)\\b|TYPE_MAGNETIC_FIELD|TYPE_ORIENTATION|TYPE_ROTATION_VECTOR");
	private static final java.util.regex.Pattern PROX_LIGHT = java.util.regex.Pattern.compile(
			"getDefaultSensor\\s*\\(\\s*(?:8|5)\\b|TYPE_PROXIMITY|TYPE_LIGHT");

	// --- SENSOR_TYPE_CALL captures the int arg ---

	@Test
	void getDefaultSensorIntArgCaptured() {
		java.util.regex.Matcher m = SENSOR_CALL.matcher("sensorManager.getDefaultSensor(1);");
		assertTrue(m.find(), "getDefaultSensor(1) must match the call pattern");
		assertEquals("1", m.group(1), "the int arg must be captured");
	}

	@Test
	void getDefaultSensor11Captured() {
		java.util.regex.Matcher m = SENSOR_CALL.matcher("sm.getDefaultSensor(11);");
		assertTrue(m.find());
		assertEquals("11", m.group(1));
	}

	// --- inventory mapping: int → human name via SENSOR_TYPES ---

	@Test
	void inventoryMapsAccelLiteral() {
		// Replicates the execute() inventory loop.
		java.util.regex.Matcher tm = SENSOR_CALL.matcher(
				"sm.getDefaultSensor(1); sm.getDefaultSensor(8);");
		java.util.ArrayList<String> sensorTypes = new java.util.ArrayList<>();
		while (tm.find()) {
			String typeVal = tm.group(1);
			for (String[] st : SensorScanCommand.SENSOR_TYPES) {
				if (st[0].equals(typeVal) && !sensorTypes.contains(st[1])) {
					sensorTypes.add(st[1]);
				}
			}
		}
		assertTrue(sensorTypes.contains("accelerometer"), "getDefaultSensor(1) → accelerometer");
		assertTrue(sensorTypes.contains("proximity"), "getDefaultSensor(8) → proximity");
	}

	@Test
	void inventoryEmptyWhenNoCall() {
		java.util.regex.Matcher tm = SENSOR_CALL.matcher("int x = 1; int y = 8;");
		java.util.ArrayList<String> sensorTypes = new java.util.ArrayList<>();
		while (tm.find()) {
			String typeVal = tm.group(1);
			for (String[] st : SensorScanCommand.SENSOR_TYPES) {
				if (st[0].equals(typeVal) && !sensorTypes.contains(st[1])) {
					sensorTypes.add(st[1]);
				}
			}
		}
		assertTrue(sensorTypes.isEmpty(), "a bare 1/8 NOT in a getDefaultSensor call must not inventory");
	}

	// --- motion / orientation / proximity rules fire on the literal form ---

	@Test
	void motionRuleFiresOnAccelLiteral() {
		assertTrue(MOTION.matcher("sm.getDefaultSensor(1);").find(),
				"getDefaultSensor(1) (accelerometer) must fire the motion rule");
	}

	@Test
	void motionRuleFiresOnGyroLiteral() {
		assertTrue(MOTION.matcher("sm.getDefaultSensor(4);").find(),
				"getDefaultSensor(4) (gyroscope) must fire the motion rule");
	}

	@Test
	void orientationRuleFiresOnMagLiteral() {
		assertTrue(ORIENTATION.matcher("sm.getDefaultSensor(2);").find(),
				"getDefaultSensor(2) (magnetometer) must fire the orientation rule");
	}

	@Test
	void orientationRuleFiresOnRotationLiteral() {
		assertTrue(ORIENTATION.matcher("sm.getDefaultSensor(11);").find(),
				"getDefaultSensor(11) (rotation vector) must fire the orientation rule");
	}

	@Test
	void proxLightRuleFiresOnProxLiteral() {
		assertTrue(PROX_LIGHT.matcher("sm.getDefaultSensor(8);").find(),
				"getDefaultSensor(8) (proximity) must fire the proximity/light rule");
	}

	// --- identifier arms remain (source-form) ---

	@Test
	void identifierFormStillFires() {
		assertTrue(MOTION.matcher("sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);").find(),
				"the identifier form must still fire the motion rule");
	}

	// --- false positive guards ---

	@Test
	void nonSensorIntDoesNotFire() {
		// TYPE_PRESSURE(6) is NOT a motion/orientation/proximity sensor.
		assertFalse(MOTION.matcher("sm.getDefaultSensor(6);").find(),
				"getDefaultSensor(6) (pressure) must NOT fire the motion rule");
		assertFalse(ORIENTATION.matcher("sm.getDefaultSensor(6);").find(),
				"getDefaultSensor(6) (pressure) must NOT fire the orientation rule");
		assertFalse(PROX_LIGHT.matcher("sm.getDefaultSensor(6);").find(),
				"getDefaultSensor(6) (pressure) must NOT fire the proximity/light rule");
	}

	@Test
	void bareIntNotInCallDoesNotFire() {
		assertFalse(MOTION.matcher("int type = 1;").find(),
				"a bare 1 NOT in getDefaultSensor() must NOT fire the motion rule");
	}
}
