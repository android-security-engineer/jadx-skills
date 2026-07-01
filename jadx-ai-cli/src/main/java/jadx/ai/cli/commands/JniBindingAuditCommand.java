package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.ai.cli.util.ElfSymbols;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;
import jadx.api.ResourcesLoader;

/**
 * Cross-references the app's Java-declared {@code native} methods against the REAL {@code Java_*}
 * symbols exported by its {@code .so} libraries ({@code .dynsym} ground truth) to reveal how each
 * native method is bound to the JVM:
 *
 * <ul>
 *   <li><b>statically bound</b> — a matching mangled {@code Java_*} export exists in a {@code .so};
 *       the implementation is directly locatable ({@code readelf}/Ghidra at that symbol).</li>
 *   <li><b>dynamically registered</b> — NO matching export in any lib; the method is wired at
 *       runtime via {@code RegisterNatives}, a common tactic to hide the native surface from static
 *       analysis. These require dynamic instrumentation (Frida hook on {@code RegisterNatives}) to
 *       locate.</li>
 * </ul>
 *
 * Also reports <b>orphan exports</b>: {@code Java_*} symbols present in a {@code .so} with no
 * matching Java declaration (dead code, other apps' classes, or inner-class methods this heuristic
 * could not mangle). This is the pairing of {@code native-bridge-index} (Java side) with
 * {@code native-lib-security}'s {@code jniExports} (native side) into an actionable binding map —
 * a capability no single studied RE tool performs natively.
 *
 * <p>JNI short-name mangling per the JNI spec (§ Resolving Native Method Names): package/class
 * separators → {@code _}, {@code _}→{@code _1}, {@code ;}→{@code _2}, {@code [}→{@code _3}, any
 * other non-ASCII-alnum char → {@code _0XXXX}. Overloaded methods append {@code __} + mangled arg
 * descriptor, which we accept via a prefix match.</p>
 */
@Command(name = "jni-binding-audit", description = "Cross-reference Java native methods against real .so Java_* exports (static vs RegisterNatives)")
public class JniBindingAuditCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Only audit classes under this package prefix")
	protected String packageFilter;

	@Option(names = { "--limit" }, description = "Maximum native methods to audit", defaultValue = "1000")
	protected int limit = 1000;

	/** Cap raw read per .so (64 MiB), matching NativeLibsCommand/NativeLibSecurityCommand. */
	private static final long MAX_LIB_BYTES = 67108864L;

	// `... native <ret> name(...)` — same shape native-bridge-index uses.
	private static final Pattern NATIVE_METHOD = Pattern.compile(
			"(?:public|private|protected|static|final|synchronized|\\s)*\\bnative\\b[\\w<>\\[\\].,?\\s]*?\\b(\\w+)\\s*\\(([^)]*)\\)");

	@Override
	protected void applyArgs(Map<String, Object> args) {
		this.packageFilter = (String) args.get("package");
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		// 1) Gather every Java_* export across all bundled .so libraries (ground truth, survives strip).
		//    exportToLib maps a Java_* symbol -> the first lib that exports it.
		Map<String, String> exportToLib = new LinkedHashMap<>();
		List<String> analyzedLibs = new ArrayList<>();
		for (ResourceFile res : decompiler.getResources()) {
			if (res.getType() != ResourceType.LIB) {
				continue;
			}
			String libName = res.getOriginalName();
			if (libName == null || !libName.toLowerCase(Locale.ROOT).endsWith(".so")) {
				continue;
			}
			byte[] data;
			try {
				data = ResourcesLoader.decodeStream(res,
						(size, is) -> is.readNBytes((int) Math.min(MAX_LIB_BYTES, Integer.MAX_VALUE)));
			} catch (Exception e) {
				continue;
			}
			if (data == null || data.length < 64) {
				continue;
			}
			ElfSymbols syms = ElfSymbols.parse(data, 1_000_000);
			if (!syms.parsed) {
				continue;
			}
			analyzedLibs.add(libName);
			for (String sym : syms.jniExports) {
				exportToLib.putIfAbsent(sym, shortLibName(libName));
			}
		}

		// 2) Walk Java native methods and classify each against the export set.
		List<Map<String, Object>> methods = new ArrayList<>();
		Set<String> matchedExports = new LinkedHashSet<>();
		int staticCount = 0;
		int dynamicCount = 0;
		boolean truncated = false;

		for (JavaClass cls : decompiler.getClasses()) {
			if (methods.size() >= limit) {
				truncated = true;
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
			if (code == null || code.isEmpty() || !code.contains("native")) {
				continue;
			}
			Matcher nm = NATIVE_METHOD.matcher(code);
			while (nm.find() && methods.size() < limit) {
				String methodName = nm.group(1);
				String expected = mangledPrefix(fullName, methodName);
				String boundLib = resolveExport(exportToLib, expected, matchedExports);

				Map<String, Object> m = new LinkedHashMap<>();
				m.put("className", fullName);
				m.put("methodName", methodName);
				m.put("expectedSymbol", expected);
				if (boundLib != null) {
					m.put("binding", "static");
					m.put("boundIn", boundLib);
					staticCount++;
				} else {
					m.put("binding", "dynamic");
					m.put("detail", "no matching Java_* export — registered at runtime via RegisterNatives");
					dynamicCount++;
				}
				methods.add(m);
			}
		}

		// 3) Orphan exports: Java_* present in a .so but never matched to a Java declaration.
		List<Map<String, Object>> orphans = new ArrayList<>();
		for (Map.Entry<String, String> e : exportToLib.entrySet()) {
			if (!matchedExports.contains(e.getKey())) {
				Map<String, Object> o = new LinkedHashMap<>();
				o.put("symbol", e.getKey());
				o.put("lib", e.getValue());
				orphans.add(o);
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("analyzedLibraries", analyzedLibs);
		data.put("jniExportCount", exportToLib.size());
		data.put("nativeMethodCount", methods.size());
		data.put("staticallyBound", staticCount);
		data.put("dynamicallyRegistered", dynamicCount);
		data.put("dynamicRegistrationDetected", dynamicCount > 0);
		data.put("methods", methods);
		data.put("orphanExports", orphans);
		data.put("orphanExportCount", orphans.size());
		data.put("truncated", truncated);
		return JsonOutput.ok(data);
	}

	/**
	 * Match a native method's expected {@code Java_*} prefix against the export set, accepting the
	 * exact non-overloaded name or an overload ({@code prefix + "__" + argDescriptor}). Records the
	 * concrete export(s) consumed so orphan detection is accurate.
	 */
	private static String resolveExport(Map<String, String> exportToLib, String expected, Set<String> matched) {
		String exactLib = exportToLib.get(expected);
		if (exactLib != null) {
			matched.add(expected);
			return exactLib;
		}
		String overloadPrefix = expected + "__";
		String lib = null;
		for (Map.Entry<String, String> e : exportToLib.entrySet()) {
			if (e.getKey().startsWith(overloadPrefix)) {
				matched.add(e.getKey());
				if (lib == null) {
					lib = e.getValue();
				}
			}
		}
		return lib;
	}

	/** {@code Java_} + mangle(fqcn with package/inner separators) + {@code _} + mangle(method). */
	// package-private for direct unit testing of the subtle JNI name mangling.
	static String mangledPrefix(String fqcn, String method) {
		// getFullName() is dotted for both packages and inner classes; JNI internal form uses '/'
		// for packages and '$' for inner classes. We can't distinguish here, so treat '.' as a
		// package separator ('/' → '_'); inner-class native methods (rare) may fall to orphanExports.
		String internal = fqcn.replace('.', '/');
		return "Java_" + mangle(internal) + "_" + mangle(method);
	}

	private static String mangle(String s) {
		StringBuilder b = new StringBuilder(s.length() + 8);
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '/') {
				b.append('_');
			} else if (c == '_') {
				b.append("_1");
			} else if (c == ';') {
				b.append("_2");
			} else if (c == '[') {
				b.append("_3");
			} else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				b.append(c);
			} else {
				b.append(String.format("_0%04x", (int) c));
			}
		}
		return b.toString();
	}

	private static String shortLibName(String path) {
		String p = path.replace('\\', '/');
		int slash = p.lastIndexOf('/');
		return slash >= 0 ? p.substring(slash + 1) : p;
	}

	@Override
	protected String getDaemonCommandName() {
		return "jni-binding-audit";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		if (packageFilter != null) {
			args.put("package", packageFilter);
		}
		args.put("limit", limit);
		return args;
	}
}
