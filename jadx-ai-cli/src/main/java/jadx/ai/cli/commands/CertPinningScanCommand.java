package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.ManifestUtil;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Certificate-pinning posture inventory — MASVS MSTG-NETWORK-4. Native: reads jadx's parsed model
 * and decoded resources, no external tool.
 *
 * <p>The <em>inverse</em> of {@code ssl-scan}, which hunts pinning-defeating bugs (trust-all
 * {@code TrustManager}s, {@code ALLOW_ALL} hostname verifiers). This command inventories the
 * pinning <b>defence</b> itself and answers a single question for an MITM-resistance review: does the
 * app pin, by which mechanism, and for which hosts? It recognises every common mechanism, not just
 * the Network Security Config {@code <pin-set>} that {@code network-security-config} already reports:
 * <ul>
 *   <li>OkHttp {@code CertificatePinner} ({@code .certificatePinner(} / {@code .add("host","sha256/..")})</li>
 *   <li>raw {@code sha256/} / {@code sha1/} pin literals (host extracted when on an {@code .add(} line)</li>
 *   <li>TrustKit</li>
 *   <li>a custom {@code X509TrustManager} that compares a public-key / certificate digest (pin-by-pubkey)</li>
 *   <li>NSC {@code <pin-set>} domains from {@code network_security_config.xml}</li>
 * </ul>
 *
 * <p>Inventory shape (no severity — pinning is a defence; its <em>absence</em> is the concern and is
 * surfaced as {@code pinsCertificates=false}, since absence can't be pinned to a line), like
 * {@code tamper-detection-scan}.
 *
 * Returns {@code {findings:[{mechanism,source,lineNumber,host,detail}], count, pinsCertificates,
 * mechanisms, pinnedHosts, truncated}}.
 */
@Command(name = "cert-pinning-scan",
		description = "Inventory certificate-pinning posture (MASVS MSTG-NETWORK-4): OkHttp CertificatePinner, raw sha256/sha1 pins, TrustKit, custom X509TrustManager pin-by-pubkey, and NSC <pin-set> domains. The defence-posture inverse of ssl-scan; answers does-this-app-resist-MITM with which hosts pinned")
public class CertPinningScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	/** Gate: only line-scan a class that touches any pinning mechanism. */
	private static final Pattern PIN_MARKER = Pattern.compile(
			"CertificatePinner|sha256/|sha1/|TrustKit|X509TrustManager");

	private static final Pattern OKHTTP_PINNER = Pattern.compile("CertificatePinner");
	private static final Pattern PIN_LITERAL = Pattern.compile("(sha256/[A-Za-z0-9+/=]+|sha1/[A-Za-z0-9+/=]+)");
	private static final Pattern TRUSTKIT = Pattern.compile("TrustKit");
	/** Host argument of an OkHttp {@code .add("host", "sha256/...")} (or pinner builder) call. */
	private static final Pattern ADD_HOST = Pattern.compile("\\.add\\s*\\(\\s*\"([^\"]+)\"");
	/** A custom TrustManager that compares key/cert material = pin-by-pubkey. */
	private static final Pattern TRUSTMANAGER = Pattern.compile("X509TrustManager");
	private static final Pattern PUBKEY_COMPARE = Pattern.compile(
			"getPublicKey\\s*\\(|getEncoded\\s*\\(|MessageDigest|getSerialNumber\\s*\\(");
	/** Pull domains out of NSC {@code <domain ...>host</domain>}. */
	private static final Pattern NSC_DOMAIN = Pattern.compile("<domain[^>]*>([^<]+)</domain>");

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
		TreeSet<String> mechanisms = new TreeSet<>();
		TreeSet<String> pinnedHosts = new TreeSet<>();

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
			if (code == null || code.isEmpty() || !PIN_MARKER.matcher(code).find()) {
				continue;
			}

			// pin-by-pubkey: a custom TrustManager that actually inspects key/cert material.
			boolean customPinManager = TRUSTMANAGER.matcher(code).find() && PUBKEY_COMPARE.matcher(code).find();
			boolean reportedOkhttp = false;
			boolean reportedTrustkit = false;
			boolean reportedCustom = false;

			String[] lines = code.split("\n", -1);
			for (int i = 0; i < lines.length && findings.size() < limit; i++) {
				String line = lines[i];

				Matcher pl = PIN_LITERAL.matcher(line);
				if (pl.find()) {
					String host = null;
					Matcher hm = ADD_HOST.matcher(line);
					if (hm.find()) {
						host = hm.group(1);
						pinnedHosts.add(host);
					}
					mechanisms.add("okhttp_pin");
					findings.add(finding("okhttp_pin", fullName, i + 1, host,
							"Public-key pin literal (" + pl.group(1) + ")" + (host != null ? " for host \"" + host + "\"" : "")));
					continue;
				}

				if (!reportedOkhttp && OKHTTP_PINNER.matcher(line).find()) {
					mechanisms.add("okhttp_certificate_pinner");
					findings.add(finding("okhttp_certificate_pinner", fullName, i + 1, null,
							"OkHttp CertificatePinner configured — pins certificates for the OkHttpClient"));
					reportedOkhttp = true;
					continue;
				}

				if (!reportedTrustkit && TRUSTKIT.matcher(line).find()) {
					mechanisms.add("trustkit");
					findings.add(finding("trustkit", fullName, i + 1, null,
							"TrustKit pinning library in use — pins per its network-security-config policy"));
					reportedTrustkit = true;
					continue;
				}

				if (customPinManager && !reportedCustom && TRUSTMANAGER.matcher(line).find()) {
					mechanisms.add("custom_trustmanager_pin");
					findings.add(finding("custom_trustmanager_pin", fullName, i + 1, null,
							"Custom X509TrustManager compares public-key/certificate material — pin-by-pubkey; verify it actually rejects on mismatch (not a trust-all stub)"));
					reportedCustom = true;
				}
			}
		}

		// NSC <pin-set> domains — the declarative mechanism (also reported by network-security-config).
		if (findings.size() < limit) {
			String nsc = ManifestUtil.loadResourceText(decompiler, "network_security_config");
			if (nsc != null && nsc.contains("<pin-set")) {
				mechanisms.add("nsc_pin_set");
				List<String> domains = ManifestUtil.extractAll(nsc, NSC_DOMAIN.pattern());
				if (domains.isEmpty()) {
					findings.add(finding("nsc_pin_set", "network_security_config.xml", 0, null,
							"Network Security Config declares a <pin-set>"));
				}
				for (String d : domains) {
					String host = d.trim();
					pinnedHosts.add(host);
					findings.add(finding("nsc_pin_set", "network_security_config.xml", 0, host,
							"Network Security Config <pin-set> pins host \"" + host + "\""));
					if (findings.size() >= limit) {
						break;
					}
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("pinsCertificates", !mechanisms.isEmpty());
		data.put("mechanisms", new ArrayList<>(mechanisms));
		data.put("pinnedHosts", new ArrayList<>(pinnedHosts));
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> finding(String mechanism, String source, int line, String host, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("mechanism", mechanism);
		f.put("source", source);
		f.put("lineNumber", line);
		f.put("host", host);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "cert-pinning-scan";
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
