package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

/**
 * Indexes the native/JS boundary of an app: JNI native methods and the libraries they bind to,
 * plus WebView JavaScript bridges ({@code addJavascriptInterface} + {@code @JavascriptInterface}).
 * These are high-value targets for hooking and a common source of vulnerabilities. Native
 * capability — reads jadx's parsed model, no external tool.
 */
@Command(name = "native-bridge-index", description = "Index JNI native methods and WebView JavaScript bridges")
public class NativeBridgeIndexCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only scan classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "-k", "--kind" }, description = "What to index: jni, jsbridge, all", defaultValue = "all")
	protected String kind = "all";

	@Option(names = { "--limit" }, description = "Maximum entries", defaultValue = "500")
	protected int limit = 500;

	// `... native <ret> name(...)` method declaration.
	private static final Pattern NATIVE_METHOD = Pattern.compile(
			"(?:public|private|protected|static|final|synchronized|\\s)*\\bnative\\b[\\w<>\\[\\].,?\\s]*?\\b(\\w+)\\s*\\(([^)]*)\\)");
	private static final Pattern LOAD_LIBRARY = Pattern.compile("System\\.(?:loadLibrary|load)\\s*\\(\\s*\"([^\"]+)\"");
	private static final Pattern ADD_JS_INTERFACE = Pattern.compile("addJavascriptInterface\\s*\\(\\s*([^,]+),\\s*\"([^\"]+)\"");
	private static final Pattern JS_ANNOTATION = Pattern.compile("@JavascriptInterface\\b[\\s\\S]{0,200}?\\b(\\w+)\\s*\\(([^)]*)\\)");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.get("kind") != null) {
			this.kind = (String) args.get("kind");
		}
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		boolean wantJni = "all".equals(kind) || "jni".equals(kind);
		boolean wantJs = "all".equals(kind) || "jsbridge".equals(kind);

		List<Map<String, Object>> entries = new ArrayList<>();

		for (JavaClass cls : decompiler.getClasses()) {
			if (entries.size() >= limit) {
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

			if (wantJni) {
				Matcher nm = NATIVE_METHOD.matcher(code);
				while (nm.find() && entries.size() < limit) {
					entries.add(entry("jni", fullName, nm.group(1), nm.group(2).trim(),
							"native method"));
				}
				Matcher ll = LOAD_LIBRARY.matcher(code);
				while (ll.find() && entries.size() < limit) {
					entries.add(entry("jni-lib", fullName, null, null,
							"loads native library: " + ll.group(1)));
				}
			}
			if (wantJs) {
				Matcher ji = ADD_JS_INTERFACE.matcher(code);
				while (ji.find() && entries.size() < limit) {
					entries.add(entry("jsbridge-binding", fullName, null, null,
							"exposes JS interface name: " + ji.group(2)));
				}
				Matcher ann = JS_ANNOTATION.matcher(code);
				while (ann.find() && entries.size() < limit) {
					entries.add(entry("jsbridge-method", fullName, ann.group(1), ann.group(2).trim(),
							"@JavascriptInterface method"));
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("entries", entries);
		data.put("count", entries.size());
		data.put("truncated", entries.size() >= limit);
		return JsonOutput.ok(data);
	}

	private static Map<String, Object> entry(String kind, String className, String method,
			String signature, String detail) {
		Map<String, Object> e = new LinkedHashMap<>();
		e.put("kind", kind);
		e.put("className", className);
		if (method != null) {
			e.put("methodName", method);
		}
		if (signature != null) {
			e.put("signature", signature);
		}
		e.put("detail", detail);
		return e;
	}

	@Override
	protected String getDaemonCommandName() {
		return "native-bridge-index";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("kind", kind);
		args.put("limit", limit);
		return args;
	}
}
