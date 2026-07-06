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
import jadx.api.ResourceFile;

/**
 * Scans for Bluetooth capability use — a privacy and exfiltration surface (device discovery,
 * pairing, GATT data transfer) and a coarse-location side-channel historically (BLE scanning
 * before Android 12 needed no location permission). Covers {@link android.bluetooth.
 * BluetoothAdapter}/{@code BluetoothGatt}/{@code BluetoothServerSocket} and the BLE scan APIs
 * ({@code startScan / startLeScan / ScanCallback}), plus the manifest {@code BLUETOOTH_*
 * } permissions. Reports the scan/connect/data classes and whether the app pairs or accepts
 * inbound connections. MASVS MSTG-PRIVACY / MSTG-NETWORK. Distinct from {@code nfc-scan}
 * (near-field channel) and {@code network-traffic-scan} (IP traffic) — this is the
 * Bluetooth/BLE channel.
 *
 * <p>Returns {@code {findings, count, highSeverityCount, usesBluetooth, bleScan,
 * acceptsConnections, bluetoothPermissions}}.
 */
@Command(name = "bluetooth-scan",
		description = "Scan for Bluetooth capability (adapter/gatt/socket, BLE scan, BLUETOOTH_* permissions)")
public class BluetoothScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern BT_MARKER = Pattern.compile(
			"BluetoothAdapter|BluetoothGatt|BluetoothDevice|BluetoothSocket|BluetoothServerSocket|"
					+ "BluetoothManager|BluetoothLeScanner|startLeScan|startScan|ScanCallback|android\\.bluetooth");

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

	private static final List<Rule> RULES = List.of(
			new Rule("startLeScan\\s*\\(|startScan\\s*\\(|\\.startScan\\s*\\(",
					"bt_ble_scan", "medium",
					"BLE scan (startLeScan / BluetoothLeScanner.startScan) — discovers nearby Bluetooth beacons; pre-Android 12 this was a coarse-location side-channel needing no location permission"),
			new Rule("BluetoothGatt|connectGatt\\s*\\(|\\.connect\\s*\\(.*Bluetooth|discoverServices\\s*\\(",
					"bt_gatt_connect", "medium",
					"BluetoothGatt connect/discoverServices — connects to a GATT server device and enumerates services/characteristics (read/write data over BLE)"),
			new Rule("writeCharacteristic\\s*\\(|readCharacteristic\\s*\\(|onCharacteristicChanged",
					"bt_gatt_io", "medium",
					"BluetoothGatt write/readCharacteristic — data transfer over BLE; verify the characteristic is not exfiltrating sensitive data"),
			new Rule("listenUsingRfcommWithServiceRecord\\s*\\(|listenUsing\\s*\\w+\\s*\\(|BluetoothServerSocket",
					"bt_accept_connection", "high",
					"BluetoothServerSocket / listenUsing* — accepts inbound Bluetooth connections; an externally-reachable server surface over the Bluetooth channel"),
			new Rule("createRfcommSocketToServiceRecord\\s*\\(|BluetoothSocket|\\.connect\\s*\\(.*Socket",
					"bt_connect", "medium",
					"BluetoothSocket connect — opens an RFCOMM/L2CAP channel to a peer device; pairing + data exfiltration path"),
			new Rule("startDiscovery\\s*\\(|getBondedDevices\\s*\\(|getBondedDevice",
					"bt_discovery", "low",
					"BluetoothAdapter.startDiscovery / getBondedDevices — enumerates discoverable and already-paired devices (privacy: device fingerprint)"),
			new Rule("BluetoothAdapter\\.getDefaultAdapter\\s*\\(|getSystemService\\s*\\(.*BLUETOOTH",
					"bt_adapter_init", "low",
					"Obtains the BluetoothAdapter — the entry point for any Bluetooth operation; corroborates an active (not just imported) Bluetooth flow"));

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
		boolean usesBluetooth = false;
		boolean bleScan = false;
		boolean acceptsConnections = false;
		List<String> bluetoothPermissions = new ArrayList<>();

		String manifest = loadManifest(decompiler);
		if (manifest != null) {
			for (String perm : new String[] { "BLUETOOTH", "BLUETOOTH_ADMIN", "BLUETOOTH_CONNECT",
					"BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE" }) {
				if (manifest.contains(perm)) {
					bluetoothPermissions.add(perm);
				}
			}
		}

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
			if (code == null || code.isEmpty() || !BT_MARKER.matcher(code).find()) {
				continue;
			}
			usesBluetooth = true;

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
					}
					if ("bt_ble_scan".equals(r.kind)) {
						bleScan = true;
					}
					if ("bt_accept_connection".equals(r.kind)) {
						acceptsConnections = true;
					}
					break;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("usesBluetooth", usesBluetooth);
		data.put("bleScan", bleScan);
		data.put("acceptsConnections", acceptsConnections);
		data.put("bluetoothPermissions", bluetoothPermissions);
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

	private static String loadManifest(JadxDecompiler decompiler) {
		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name != null && name.replace('\\', '/').endsWith("AndroidManifest.xml")) {
				try {
					return res.loadContent().getText().toString();
				} catch (Exception e) {
					return null;
				}
			}
		}
		return null;
	}

	@Override
	protected String getDaemonCommandName() {
		return "bluetooth-scan";
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
