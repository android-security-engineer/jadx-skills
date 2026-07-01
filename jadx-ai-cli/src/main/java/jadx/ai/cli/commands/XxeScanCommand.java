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
 * XML External Entity (XXE) injection scanner — MASVS MSTG-PLATFORM / OWASP A05. Native: reads
 * jadx's parsed model, no external tool.
 *
 * <p>Complements (does not duplicate) {@code serialization-scan}, which only notes the <em>presence</em>
 * of an XML parser factory as {@code info}. This scanner makes the actual XXE decision: an XML
 * parser is dangerous when it is instantiated <b>without entity hardening</b>. The robust hardenings
 * recognised here (any one, anywhere in the same class, marks it safe) are the OWASP-recommended
 * settings: {@code FEATURE_SECURE_PROCESSING}, the {@code disallow-doctype-decl} feature,
 * {@code setExpandEntityReferences(false)}, the {@code external-general-entities} /
 * {@code external-parameter-entities} features set false, and emptying
 * {@code ACCESS_EXTERNAL_DTD} / {@code ACCESS_EXTERNAL_SCHEMA}.
 *
 * <p>Heuristic: hardening is scoped to the class containing the factory (the common idiom — configure
 * the factory right where it's built). A factory with no hardening marker in its class is flagged
 * {@code xxe_unhardened_parser/high}; an explicit {@code setExpandEntityReferences(true)} or
 * {@code setXIncludeAware(true)} is {@code xxe_entity_expansion_enabled/high} regardless. A hardened
 * class reports {@code xxe_hardened/info}.
 *
 * Returns {@code {findings:[{kind,severity,className,lineNumber,detail}], count, highSeverityCount,
 * hardenedClasses, truncated}}.
 */
@Command(name = "xxe-scan",
		description = "Detect XML External Entity (XXE) injection: XML parser factories (DocumentBuilder/SAXParser/XMLInputFactory/Transformer/SAXReader/XmlPullParser...) instantiated without entity hardening (FEATURE_SECURE_PROCESSING / disallow-doctype-decl / setExpandEntityReferences(false) / ACCESS_EXTERNAL_*). Unlike serialization-scan, evaluates the secure-config, not just factory presence")
public class XxeScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Class-level gate: only consider classes that build an XML parser. */
	private static final Pattern XML_PARSER_MARKER = Pattern.compile(
			"DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|"
					+ "XPathFactory|XMLReaderFactory|XmlPullParserFactory|SAXBuilder|SAXReader|DocumentBuilder");

	/** A factory/parser is actually instantiated on this line — the sink to flag. */
	private static final Pattern FACTORY_INSTANTIATION = Pattern.compile(
			"DocumentBuilderFactory\\.newInstance\\s*\\(|SAXParserFactory\\.newInstance\\s*\\(|"
					+ "XMLInputFactory\\.(?:newInstance|newFactory)\\s*\\(|TransformerFactory\\.newInstance\\s*\\(|"
					+ "SchemaFactory\\.newInstance\\s*\\(|XPathFactory\\.newInstance\\s*\\(|"
					+ "XMLReaderFactory\\.createXMLReader\\s*\\(|XmlPullParserFactory\\.newInstance\\s*\\(|"
					+ "new\\s+SAXBuilder\\s*\\(|new\\s+SAXReader\\s*\\(|newDocumentBuilder\\s*\\(|newSAXParser\\s*\\(");

	/** Any of these in the same class = the parser is hardened against entity expansion / external refs. */
	private static final Pattern HARDENED = Pattern.compile(
			"FEATURE_SECURE_PROCESSING|disallow-doctype-decl|"
					+ "setExpandEntityReferences\\s*\\(\\s*false|"
					+ "external-general-entities|external-parameter-entities|"
					+ "ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA|"
					+ "setXIncludeAware\\s*\\(\\s*false|XMLConstants\\.FEATURE_SECURE_PROCESSING");

	/**
	 * Explicit re-enable of a dangerous XML feature — high regardless of other hardening.
	 * <ul>
	 *   <li>{@code setExpandEntityReferences(true)} — re-enables external entity expansion (XXE).</li>
	 *   <li>{@code setXIncludeAware(true)} — enables XInclude processing; an attacker can pull in
	 *       arbitrary external files via {@code <xi:include href="...">}. The {@code false} form is in
	 *       {@link #HARDENED}; the {@code true} form was previously NOT flagged — a symmetric gap.</li>
	 * </ul>
	 * Package-private so a test can assert both dangerous forms fire.
	 */
	static final Pattern EXPLICIT_DANGER = Pattern.compile(
			"setExpandEntityReferences\\s*\\(\\s*true|setXIncludeAware\\s*\\(\\s*true");

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
		int hardenedClasses = 0;

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
			if (code == null || code.isEmpty() || !XML_PARSER_MARKER.matcher(code).find()) {
				continue;
			}

			boolean classHardened = HARDENED.matcher(code).find();
			String[] lines = code.split("\n", -1);
			boolean reportedUnhardened = false;

			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				if (isXxeExplicitDanger(line)) {
					findings.add(finding("xxe_entity_expansion_enabled", "high", fullName, i + 1,
							"Explicitly enabled a dangerous XML feature (setExpandEntityReferences(true) / "
									+ "setXIncludeAware(true)) — re-enables entity expansion or XInclude, XXE-exploitable "
									+ "regardless of other hardening"));
					highSeverityCount++;
					continue;
				}

				if (!classHardened && !reportedUnhardened && FACTORY_INSTANTIATION.matcher(line).find()) {
					findings.add(finding("xxe_unhardened_parser", "high", fullName, i + 1,
							"XML parser instantiated with no XXE hardening in this class (no FEATURE_SECURE_PROCESSING / disallow-doctype-decl / setExpandEntityReferences(false) / ACCESS_EXTERNAL_*) — vulnerable to external-entity injection"));
					highSeverityCount++;
					reportedUnhardened = true; // one per class to avoid noise
				}
			}

			if (classHardened) {
				hardenedClasses++;
				if (findings.size() < limit) {
					findings.add(finding("xxe_hardened", "info", fullName, 0,
							"XML parser in this class applies entity hardening — XXE mitigated"));
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("highSeverityCount", highSeverityCount);
		data.put("hardenedClasses", hardenedClasses);
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	/**
	 * True if the line explicitly re-enables a dangerous XML feature (entity expansion or XInclude).
	 * Package-private so a test can assert both dangerous forms fire.
	 */
	static boolean isXxeExplicitDanger(String line) {
		return line != null && EXPLICIT_DANGER.matcher(line).find();
	}

	private static Map<String, Object> finding(String kind, String severity, String cls, int line, String detail) {
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
		return "xxe-scan";
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
