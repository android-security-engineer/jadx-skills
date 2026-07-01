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
 * Scans for NFC handling — an externally-reachable attack surface where another app or a
 * physical tag can dispatch an intent into the app. Covers manifest NFC intent-filters
 * ({@code ACTION_NDEF_DISCOVERED / ACTION_TECH_DISCOVERED / ACTION_TAG_DISCOVERED} + the
 * {@code <tech-list>}), and the runtime API: {@code Ndef} read/write, {@code NdefMessage}
 * parsing, {@code enableForegroundDispatch} / {@code enableReaderMode}, and tag I/O
 * ({@code transceive} / {@code MifareClassic} / {@code IsoDep}). Risky shapes: writing
 * attacker-controlled NDEF to a writable tag, or trusting tag payloads without validation.
 * MASVS MSTG-PLATFORM. Distinct from {@code deeplink-scan} (URI attack surface) and
 * {@code intent-scan} (IPC) — this is the NFC channel.
 *
 * <p>Returns {@code {findings, count, highSeverityCount, handlesNfc, hasNfcManifestFilter,
 * nfcTechList, hasNdefWrite}}.
 */
@Command(name = "nfc-scan",
		description = "Scan for NFC intent handling + Ndef read/write + foreground dispatch (NFC attack surface)")
public class NfcScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "200")
	protected int limit = 200;

	private static final Pattern NFC_MARKER = Pattern.compile(
			"android\\.nfc|NfcAdapter|NdefMessage|NdefRecord|Ndef\\.|NfcManager|"
					+ "ACTION_NDEF_DISCOVERED|ACTION_TECH_DISCOVERED|ACTION_TAG_DISCOVERED|Tag\\b");

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
			new Rule("ACTION_NDEF_DISCOVERED|ACTION_TECH_DISCOVERED|ACTION_TAG_DISCOVERED",
					"nfc_intent_filter", "medium",
					"NFC intent-filter action — the app is launched when a tag matching its filter is scanned; an externally-reachable entry point (verify payload handling)"),
			new Rule("enableForegroundDispatch\\s*\\(|enableReaderMode\\s*\\(",
					"nfc_foreground_dispatch", "medium",
					"NfcAdapter.enableForegroundDispatch / enableReaderMode — app actively grabs NFC events while foregrounded; pairs with tag I/O"),
			new Rule("\\.writeNdefMessage\\s*\\(|\\.writeNdef\\s*\\(|new\\s+NdefMessage\\s*\\(",
					"nfc_ndef_write", "high",
					"Writes an NdefMessage to a tag (writeNdefMessage / writeNdef / new NdefMessage) — can overwrite/corrupt writable tags; verify the message source is not attacker-controlled"),
			new Rule("\\.getNdefMessage\\s*\\(|createNdefMessage\\s*\\(|NdefRecord\\.create",
					"nfc_ndef_parse", "low",
					"Parses/constructs NdefMessage — the data path from a tag payload into app logic; validate before use"),
			new Rule("\\.transceive\\s*\\(|MifareClassic|IsoDep|MifareUltralight",
					"nfc_tag_io", "medium",
					"Low-level tag I/O (transceive / MifareClassic / IsoDep) — raw APDU/protocol exchanges with the tag, prone to injection if commands are built from untrusted data"),
			new Rule("\\.connect\\s*\\(.*\\).*\\bTag\\b|Tag\\.getTechList",
					"nfc_tag_connect", "low",
					"Connects to a Tag and enumerates its supported tech list — the setup step before tag I/O"));

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
		boolean handlesNfc = false;
		boolean hasNdefWrite = false;
		boolean hasNfcManifestFilter = false;
		List<String> nfcTechList = new ArrayList<>();

		String manifest = loadManifest(decompiler);
		if (manifest != null) {
			if (manifest.contains("ACTION_NDEF_DISCOVERED")
					|| manifest.contains("ACTION_TECH_DISCOVERED")
					|| manifest.contains("ACTION_TAG_DISCOVERED")) {
				hasNfcManifestFilter = true;
			}
			// <tech> entries inside a tech-list xml resource
			java.util.regex.Matcher techM = Pattern.compile(
					"<tech\\b[^>]*>\\s*([\\w.]+)\\s*</tech>").matcher(manifest);
			while (techM.find()) {
				nfcTechList.add(techM.group(1));
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
			if (code == null || code.isEmpty() || !NFC_MARKER.matcher(code).find()) {
				continue;
			}
			handlesNfc = true;

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
						hasNdefWrite = true;
					}
					break;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("handlesNfc", handlesNfc || hasNfcManifestFilter);
		data.put("hasNfcManifestFilter", hasNfcManifestFilter);
		data.put("hasNdefWrite", hasNdefWrite);
		data.put("nfcTechList", nfcTechList);
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
		return "nfc-scan";
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
