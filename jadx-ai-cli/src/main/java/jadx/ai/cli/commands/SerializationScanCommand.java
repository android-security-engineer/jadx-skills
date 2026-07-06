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
 * Scans decompiled code for insecure object (de)serialization — MASVS MSTG-PLATFORM / MSTG-CODE.
 * Native: reads jadx's parsed model, no external tool.
 *
 * <p>Java/Android serialization is a recurring RCE / object-injection surface. The line-level rules:
 * <ul>
 *   <li><b>Java deserialization</b> — {@code ObjectInputStream.readObject()} /
 *       {@code readUnshared()} / {@code XMLDecoder.readObject()}, the classic gadget-chain entry
 *       point. High (object injection if the stream is attacker-controlled).</li>
 *   <li><b>Untrusted Serializable from IPC</b> — {@code getSerializableExtra(} /
 *       {@code getParcelableExtra(} from an Intent, then cast to an app type: a malicious app can
 *       hand over a forged object. Medium.</li>
 *   <li><b>Unsafe XML/object readers</b> — {@code SAXParser}/{@code DocumentBuilder} without
 *       {@code setFeature(...disallow-doctype...)} (XXE neighbour). We flag the reader; XXE-specific
 *       hardening absence is reported as info.</li>
 *   <li><b>Gson/Jackson polymorphic typing</b> — {@code enableDefaultTyping(} /
 *       {@code @JsonTypeInfo} / {@code activateDefaultTyping(} / Gson {@code RuntimeTypeAdapterFactory}:
 *       runtime type-polymorphic deserialization, a known gadget surface (the type discriminator is
 *       attacker-controlled). High.</li>
 *   <li><b>Custom readObject</b> — a class implementing {@code Serializable} that defines a private
 *       {@code readObject(ObjectInputStream)} — info, worth a manual look.</li>
 * </ul>
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * truncated}}.
 */
@Command(name = "serialization-scan",
		description = "Scan code for insecure deserialization (ObjectInputStream.readObject, Jackson default typing, untrusted Serializable from IPC, XXE-prone parsers)")
public class SerializationScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Cheap class-level gate: only classes that touch (de)serialization at all. */
	private static final Pattern SERDE_MARKER = Pattern.compile(
			"ObjectInputStream|readObject|readUnshared|XMLDecoder|getSerializableExtra|getParcelableExtra|getParcelableArrayExtra|getParcelableArrayListExtra|enableDefaultTyping|activateDefaultTyping|RuntimeTypeAdapterFactory|JsonTypeInfo|SAXParser|DocumentBuilder|XMLReader|Serializable");

	/**
	 * Untrusted Serializable/Parcelable object read from an Intent — all the Bundle getters that hand
	 * back an attacker-forgeable object. Package-private so a test can assert the modern variants
	 * ({@code getParcelableArrayExtra}/{@code getParcelableArrayListExtra} smuggle a list/array of
	 * Parcelable, and API 33+ {@code getSerializable(name, Class.class)} is a two-arg overload).
	 */
	static final Pattern IPC_OBJECT_SOURCE = Pattern.compile(
			"getSerializableExtra\\s*\\(|getSerializable\\s*\\(|getParcelableExtra\\s*\\(|"
					+ "getParcelableArrayExtra\\s*\\(|getParcelableArrayListExtra\\s*\\(|"
					+ "getSerializableArrayListExtra\\s*\\(");

	/**
	 * Gson {@code RuntimeTypeAdapterFactory} — runtime type-polymorphic deserialization where the type
	 * discriminator is an attacker-controlled JSON field, the Gson equivalent of Jackson default
	 * typing. Package-private for testing.
	 */
	static final Pattern GSON_RUNTIME_TYPE = Pattern.compile(
			"RuntimeTypeAdapterFactory|@JsonSubTypes|registerSubtype\\s*\\(");

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
			new Rule(Pattern.compile("\\.readObject\\s*\\(|\\.readUnshared\\s*\\("),
					"java_deserialization", "high",
					"ObjectInputStream.readObject/readUnshared — Java object deserialization; if the stream is attacker-controlled this is a gadget-chain RCE entry point"),
			new Rule(Pattern.compile("XMLDecoder"),
					"xmldecoder", "high",
					"java.beans.XMLDecoder deserialization — executes arbitrary method calls from the XML; never use on untrusted input"),
			new Rule(Pattern.compile("enableDefaultTyping\\s*\\(|activateDefaultTyping\\s*\\("),
					"jackson_default_typing", "high",
					"Jackson polymorphic default typing — a well-known deserialization gadget surface; restrict with a PolymorphicTypeValidator or remove"),
			new Rule(GSON_RUNTIME_TYPE,
					"gson_runtime_type_adapter", "high",
					"Gson RuntimeTypeAdapterFactory / @JsonSubtypes — runtime type-polymorphic deserialization where the type discriminator is attacker-controlled; restrict the registered subtypes to a safe closed set"),
			new Rule(IPC_OBJECT_SOURCE,
					"untrusted_ipc_object", "medium",
					"Serializable/Parcelable read from an Intent — a malicious app can forge this object; validate type and contents before use"),
			new Rule(Pattern.compile("@JsonTypeInfo"),
					"jackson_polymorphic_annotation", "medium",
					"@JsonTypeInfo polymorphic typing — ensure the type set is restricted to a safe allowlist"),
			new Rule(Pattern.compile("newSAXParser\\s*\\(|newDocumentBuilder\\s*\\(|createXMLReader\\s*\\(|SAXParserFactory\\.newInstance|DocumentBuilderFactory\\.newInstance"),
					"xml_parser", "info",
					"XML parser created — verify DOCTYPE/external entities are disabled (setFeature disallow-doctype-decl) to prevent XXE"));

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
			if (code == null || code.isEmpty() || !SERDE_MARKER.matcher(code).find()) {
				continue;
			}

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];
				int ln = i + 1;
				for (Rule r : RULES) {
					if (r.pattern.matcher(line).find()) {
						findings.add(finding(fullName, ln, r.kind, r.severity, r.detail));
						if ("high".equals(r.severity)) {
							highSeverityCount++;
						}
						break; // one finding per line — first/most-severe rule wins
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
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
		return "serialization-scan";
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
