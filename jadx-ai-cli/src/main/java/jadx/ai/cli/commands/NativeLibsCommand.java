package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;
import jadx.api.ResourcesLoader;

/**
 * Triage the bundled native libraries — the half of an Android app jadx cannot decompile. JADX
 * stops at the Dalvik/ART boundary; everything in {@code lib/<abi>/*.so} (the JNI implementations,
 * packers' unpacking stubs, statically-linked OpenSSL, C2 URLs, anti-debug / root-detection
 * logic) is invisible to {@code secrets-scan} / {@code ioc-extract}, which only see Java. This
 * command reads each {@code .so}'s raw bytes (via {@link ResourcesLoader#decodeStream}), runs a
 * {@code strings}-style printable-ASCII extraction, surfaces the exported {@code JNI_OnLoad} /
 * {@code Java_*} symbols (the actual native attack surface that pairs with
 * {@link NativeBridgeIndexCommand}'s Java side), and categorises interesting strings
 * (URLs/IPs, dynamic loading, process exec, anti-debug/anti-frida, root detection, crypto). It is
 * a lightweight, in-process absorption of the first thing you'd do in radare2/Ghidra/IDA, with no
 * external disassembler required.
 *
 * Returns {@code {libraries:[{name,abi,sizeBytes,truncated,stringCount,jniSymbols,findings}],
 * libraryCount, findingCount, abis}}.
 */
@Command(name = "native-libs",
		description = "Triage bundled native .so libraries: strings, JNI symbols, and IOC/anti-debug/root/crypto markers")
public class NativeLibsCommand extends AbstractCommand {

	@Option(names = { "--lib" }, description = "Only analyse libraries whose path contains this substring")
	protected String libFilter;

	@Option(names = { "--min-length" }, description = "Minimum printable-string length", defaultValue = "5")
	protected int minLength = 5;

	@Option(names = { "--max-bytes" }, description = "Max bytes to read per .so (cap to bound memory)",
			defaultValue = "67108864")
	protected long maxBytes = 67108864L; // 64 MiB

	@Option(names = { "--limit" }, description = "Max findings per library", defaultValue = "100")
	protected int limit = 100;

	@Option(names = { "--all-strings" },
			description = "Also return every extracted string (capped by --limit), not just categorised findings")
	protected boolean allStrings;

	// Categorised markers. Lower-cased substring match over extracted strings.
	private static final Map<String, String[]> MARKERS = new LinkedHashMap<>();
	static {
		MARKERS.put("dynamic_load", new String[] { "dlopen", "dlsym", "android_dlopen_ext", "loadlibrary" });
		MARKERS.put("process_exec", new String[] { "/system/bin/sh", "execve", "popen", "system(", "/bin/sh" });
		MARKERS.put("anti_debug", new String[] { "ptrace", "tracerpid", "/proc/self/status", "anti_debug",
				"isdebuggerconnected" });
		MARKERS.put("anti_frida", new String[] { "frida", "gum-js-loop", "gmain", "linjector", "re.frida.server",
				"frida-agent", "xposed", "substrate" });
		MARKERS.put("root_detection", new String[] { "/system/xbin/su", "/system/bin/su", "magisk", "supersu",
				"superuser", "busybox", "/sbin/su" });
		MARKERS.put("crypto", new String[] { "openssl", "libcrypto", "-----begin", "aes_", "evp_", "boringssl" });
		MARKERS.put("packer", new String[] { "secneo", "bangcle", "ijiami", "qihoo", "jiagu", "tencent/legu",
				"naga", "apkprotect" });
	}

	private static final Pattern URL = Pattern.compile("https?://[\\w./%#?&=:+-]+", Pattern.CASE_INSENSITIVE);
	private static final Pattern IPV4 = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> libraries = new ArrayList<>();
		int totalFindings = 0;
		List<String> abis = new ArrayList<>();

		for (ResourceFile res : decompiler.getResources()) {
			if (res.getType() != ResourceType.LIB) {
				continue;
			}
			String name = res.getOriginalName();
			if (name == null || !name.toLowerCase(Locale.ROOT).endsWith(".so")) {
				continue;
			}
			if (libFilter != null && !name.contains(libFilter)) {
				continue;
			}

			byte[] bytes;
			boolean truncated;
			try {
				long cap = maxBytes;
				byte[] read = ResourcesLoader.decodeStream(res, (size, is) -> is.readNBytes((int) Math.min(cap, Integer.MAX_VALUE)));
				bytes = read != null ? read : new byte[0];
			} catch (Exception e) {
				Map<String, Object> errLib = new LinkedHashMap<>();
				errLib.put("name", name);
				errLib.put("error", "unreadable: " + e.getMessage());
				libraries.add(errLib);
				continue;
			}
			truncated = bytes.length >= maxBytes;

			List<String> strings = extractStrings(bytes, minLength);

			List<String> jniSymbols = new ArrayList<>();
			List<Map<String, Object>> findings = new ArrayList<>();
			for (String s : strings) {
				if (s.startsWith("Java_") || s.equals("JNI_OnLoad") || s.equals("JNI_OnUnload")) {
					if (jniSymbols.size() < limit && !jniSymbols.contains(s)) {
						jniSymbols.add(s);
					}
				}
			}
			scanFindings(strings, findings, limit);
			totalFindings += findings.size();

			String abi = extractAbi(name);
			if (abi != null && !abis.contains(abi)) {
				abis.add(abi);
			}

			Map<String, Object> lib = new LinkedHashMap<>();
			lib.put("name", name);
			lib.put("abi", abi);
			lib.put("sizeBytes", bytes.length);
			lib.put("truncated", truncated);
			lib.put("stringCount", strings.size());
			lib.put("jniSymbols", jniSymbols);
			lib.put("findings", findings);
			if (allStrings) {
				lib.put("strings", strings.size() > limit ? strings.subList(0, limit) : strings);
			}
			libraries.add(lib);
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("libraries", libraries);
		data.put("libraryCount", libraries.size());
		data.put("findingCount", totalFindings);
		data.put("abis", abis);
		return JsonOutput.ok(data);
	}

	/** Classic {@code strings}: runs of printable ASCII (0x20–0x7E) at least {@code minLen} long. */
	private static List<String> extractStrings(byte[] bytes, int minLen) {
		List<String> out = new ArrayList<>();
		StringBuilder cur = new StringBuilder();
		for (byte value : bytes) {
			int c = value & 0xFF;
			if (c >= 0x20 && c <= 0x7E) {
				cur.append((char) c);
			} else {
				if (cur.length() >= minLen) {
					out.add(cur.toString());
				}
				cur.setLength(0);
			}
		}
		if (cur.length() >= minLen) {
			out.add(cur.toString());
		}
		return out;
	}

	private static void scanFindings(List<String> strings, List<Map<String, Object>> findings, int limit) {
		for (String s : strings) {
			if (findings.size() >= limit) {
				return;
			}
			String lower = s.toLowerCase(Locale.ROOT);
			// IOC: URLs / IPs (skip noisy loopback/version-like).
			var um = URL.matcher(s);
			if (um.find()) {
				add(findings, "url", um.group());
				continue;
			}
			var im = IPV4.matcher(s);
			if (im.find()) {
				String ip = im.group();
				if (!ip.equals("0.0.0.0") && !ip.startsWith("127.")) {
					add(findings, "ip", ip);
					continue;
				}
			}
			for (Map.Entry<String, String[]> cat : MARKERS.entrySet()) {
				boolean hit = false;
				for (String needle : cat.getValue()) {
					if (lower.contains(needle)) {
						hit = true;
						break;
					}
				}
				if (hit) {
					add(findings, cat.getKey(), s.length() > 120 ? s.substring(0, 120) : s);
					break;
				}
			}
		}
	}

	private static void add(List<Map<String, Object>> findings, String category, String value) {
		Map<String, Object> f = new LinkedHashMap<>();
		f.put("category", category);
		f.put("value", value);
		findings.add(f);
	}

	/** {@code lib/arm64-v8a/foo.so} → {@code arm64-v8a}. */
	private static String extractAbi(String path) {
		String norm = path.replace('\\', '/');
		int li = norm.indexOf("lib/");
		if (li < 0) {
			return null;
		}
		String rest = norm.substring(li + 4);
		int slash = rest.indexOf('/');
		return slash > 0 ? rest.substring(0, slash) : null;
	}

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.get("lib") != null) {
			this.libFilter = (String) args.get("lib");
		}
		if (args.get("minLength") != null) {
			this.minLength = ((Number) args.get("minLength")).intValue();
		}
		if (args.get("maxBytes") != null) {
			this.maxBytes = ((Number) args.get("maxBytes")).longValue();
		}
		if (args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
		if (args.get("allStrings") != null) {
			this.allStrings = Boolean.TRUE.equals(args.get("allStrings"));
		}
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		if (libFilter != null) {
			args.put("lib", libFilter);
		}
		args.put("minLength", minLength);
		args.put("maxBytes", maxBytes);
		args.put("limit", limit);
		args.put("allStrings", allStrings);
		return args;
	}
}
