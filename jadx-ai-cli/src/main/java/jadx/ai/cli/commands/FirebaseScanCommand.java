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
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;

/**
 * Firebase / Google-backend reconnaissance — the apkleaks/MobSF "Firebase" capability, absorbed
 * natively. Native: reads jadx's parsed classes and decoded resources, no external tool.
 *
 * <p>Distinct from {@code secrets-scan} (entropy + generic credential regexes) and {@code ioc-extract}
 * (all URLs/IPs/domains). This command is <em>backend-service-aware</em>: it inventories which Google
 * backends the app talks to and assembles a ready-to-test recon summary. The marquee output is
 * {@code openDbCheckUrls} — each discovered Realtime Database URL with {@code /.json} appended, the
 * exact endpoint a tester fetches to confirm the classic <b>world-readable Firebase database</b>
 * misconfiguration (an unauthenticated {@code GET <db>/.json} returning data = open DB). Also
 * inventories Cloud Storage buckets ({@code *.appspot.com} / {@code gs://}), Google API keys
 * ({@code AIza...}), the mobilesdk app id ({@code 1:NN:android:HH}), and which Firebase products the
 * code initialises (Database/Firestore/Storage/Auth/Messaging/RemoteConfig/Crashlytics/Functions).
 * The {@code google-services.json} config is compiled into {@code strings.xml}/ARSC, so resources are
 * scanned by default.
 *
 * Returns {@code {findings:[{category,source,lineNumber,value,detail}], count, databaseUrls,
 * storageBuckets, apiKeys, appIds, products, openDbCheckUrls, truncated}}.
 */
@Command(name = "firebase-scan",
		description = "Firebase/Google backend recon (apkleaks/MobSF style): Realtime DB URLs (+ ready-to-test /.json open-DB check URLs), Cloud Storage buckets, Google API keys, mobilesdk app id, and which Firebase products the app uses. Scans code + strings.xml/ARSC. Backend-service-aware, unlike secrets-scan/ioc-extract")
public class FirebaseScanCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--no-resources" }, description = "Skip strings.xml/ARSC resources (scan code only)")
	protected boolean noResources;

	@Option(names = { "--limit" }, description = "Maximum number of findings", defaultValue = "300")
	protected int limit = 300;

	private static final class Rule {
		final Pattern pattern;
		final String category;
		final String detail;

		Rule(String regex, String category, String detail) {
			this.pattern = Pattern.compile(regex);
			this.category = category;
			this.detail = detail;
		}
	}

	/**
	 * Broad gate: only line-scan a class/resource whose text mentions Firebase/Google backends. Kept in
	 * sync with {@link #RULES} — every rule's anchor must appear here or a class exercising only that
	 * rule is skipped at the gate and the finding is silently dropped. The mobilesdk app id
	 * ({@code 1:NN:android:HH}, the {@code firebase_app_id} rule) is a bare string constant that can
	 * appear with NO {@code Firebase}/{@code AIza}/{@code firebaseio} reference — e.g. a build-config
	 * or analytics helper holding only the project id — so a pure app-id class was skipped and
	 * {@code firebase_app_id} never fired. Package-private so a test can assert the gate covers it.
	 */
	static final Pattern FIREBASE_MARKER = Pattern.compile(
			"firebaseio\\.com|firebasedatabase\\.app|appspot\\.com|firebasestorage|AIza|"
					+ "Firebase|gcm_defaultSenderId|google_app_id|firebase_database_url|gs://|"
					+ "\\d:\\d{6,}:android:[0-9a-fA-F]+");

	/** First matching rule wins per line; group(1) (when present) is the value to inventory. */
	private static final List<Rule> RULES = List.of(
			new Rule("(https?://[a-zA-Z0-9._\\-]+\\.(?:firebaseio\\.com|firebasedatabase\\.app)[^\\s\"'<>]*)",
					"firebase_database",
					"Firebase Realtime Database URL — test for the world-readable misconfiguration by fetching <url>/.json unauthenticated"),
			new Rule("(gs://[a-zA-Z0-9._\\-/]+)",
					"firebase_storage",
					"Firebase Cloud Storage bucket reference (gs://)"),
			new Rule("([a-zA-Z0-9._\\-]+\\.appspot\\.com)",
					"firebase_storage",
					"Firebase Cloud Storage / App Engine bucket (*.appspot.com)"),
			new Rule("(AIza[0-9A-Za-z_\\-]{35})",
					"google_api_key",
					"Google/Firebase API key (AIza...) — restrict by package & SHA-1 in the Google Cloud console"),
			new Rule("(\\d:\\d{6,}:android:[0-9a-fA-F]+)",
					"firebase_app_id",
					"Firebase mobilesdk app id (1:NN:android:HH) — identifies the Firebase project"),
			new Rule("(FirebaseDatabase|FirebaseFirestore|FirebaseStorage|FirebaseAuth|FirebaseMessaging|FirebaseRemoteConfig|FirebaseAnalytics|FirebaseCrashlytics|FirebaseFunctions|FirebaseInstanceId|FirebaseApp)",
					"firebase_product",
					"Initialises/uses a Firebase product"));

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("noResources")) {
			this.noResources = Boolean.TRUE.equals(args.get("noResources"));
		}
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> findings = new ArrayList<>();
		TreeSet<String> databaseUrls = new TreeSet<>();
		TreeSet<String> storageBuckets = new TreeSet<>();
		TreeSet<String> apiKeys = new TreeSet<>();
		TreeSet<String> appIds = new TreeSet<>();
		TreeSet<String> products = new TreeSet<>();

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
			if (code == null || code.isEmpty() || !FIREBASE_MARKER.matcher(code).find()) {
				continue;
			}
			scanText(code, fullName, findings, databaseUrls, storageBuckets, apiKeys, appIds, products);
		}

		if (!noResources && findings.size() < limit) {
			for (ResourceFile res : decompiler.getResources()) {
				if (findings.size() >= limit) {
					break;
				}
				ResourceType type = res.getType();
				if (type != ResourceType.XML && type != ResourceType.ARSC && type != ResourceType.MANIFEST) {
					continue;
				}
				try {
					var container = res.loadContent();
					if (container == null) {
						continue;
					}
					var codeInfo = container.getText();
					if (codeInfo == null) {
						continue;
					}
					String text = codeInfo.toString();
					if (!FIREBASE_MARKER.matcher(text).find()) {
						continue;
					}
					scanText(text, res.getOriginalName(), findings, databaseUrls, storageBuckets, apiKeys, appIds, products);
				} catch (Exception ignored) {
					// skip unreadable resources
				}
			}
		}

		// The headline recon artefact: the exact URL to fetch to confirm an open Realtime DB.
		TreeSet<String> openDbCheckUrls = new TreeSet<>();
		for (String url : databaseUrls) {
			String base = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
			openDbCheckUrls.add(base + "/.json");
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("findings", findings);
		data.put("count", findings.size());
		data.put("databaseUrls", new ArrayList<>(databaseUrls));
		data.put("storageBuckets", new ArrayList<>(storageBuckets));
		data.put("apiKeys", new ArrayList<>(apiKeys));
		data.put("appIds", new ArrayList<>(appIds));
		data.put("products", new ArrayList<>(products));
		data.put("openDbCheckUrls", new ArrayList<>(openDbCheckUrls));
		data.put("truncated", findings.size() >= limit);
		return JsonOutput.ok(data);
	}

	private void scanText(String text, String source, List<Map<String, Object>> findings,
			TreeSet<String> databaseUrls, TreeSet<String> storageBuckets, TreeSet<String> apiKeys,
			TreeSet<String> appIds, TreeSet<String> products) {
		String[] lines = text.split("\n", -1);
		for (int i = 0; i < lines.length && findings.size() < limit; i++) {
			String line = lines[i];
			for (Rule r : RULES) {
				Matcher m = r.pattern.matcher(line);
				if (!m.find()) {
					continue;
				}
				String value = m.groupCount() >= 1 && m.group(1) != null ? m.group(1) : m.group(0);
				switch (r.category) {
					case "firebase_database":
						databaseUrls.add(value);
						break;
					case "firebase_storage":
						storageBuckets.add(value);
						break;
					case "google_api_key":
						apiKeys.add(value);
						break;
					case "firebase_app_id":
						appIds.add(value);
						break;
					case "firebase_product":
						products.add(value);
						break;
					default:
						break;
				}
				findings.add(finding(r.category, source, i + 1, value, r.detail));
				break; // one finding per line — first (most-specific) rule wins
			}
		}
	}

	private static Map<String, Object> finding(String category, String source, int line, String value, String detail) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("category", category);
		f.put("source", source);
		f.put("lineNumber", line);
		f.put("value", value);
		f.put("detail", detail);
		return f;
	}

	@Override
	protected String getDaemonCommandName() {
		return "firebase-scan";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("noResources", noResources);
		args.put("limit", limit);
		return args;
	}
}
