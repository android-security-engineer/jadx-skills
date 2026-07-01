package jadx.ai.cli.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Infers a native library's behavioral capabilities from its imported symbols ({@code .dynsym}
 * ground truth) plus a few high-signal embedded strings — a {@code capa}-style tag set for
 * {@code .so} files. Imports are the honest signal: a lib that calls {@code ptrace}, {@code dlopen},
 * {@code mprotect}, {@code execve}, or {@code socket} is doing anti-debug, dynamic code loading,
 * self-modification/unpacking, command execution, or networking regardless of how it is named or
 * obfuscated. Pairs the {@link ElfSymbols} import list with a string scan for root/tamper detection
 * markers that have no dedicated import.
 *
 * <p>Note: JNIEnv operations (RegisterNatives, FindClass, CallObjectMethod, …) are invoked through
 * the JNIEnv function-table pointer, NOT as imported symbols, so they never appear in {@code .dynsym}
 * imports and are intentionally out of scope here.</p>
 */
public final class NativeBehavior {

	private NativeBehavior() {
	}

	/** A behavior tag: name of the capability + the concrete imports/strings that evidence it. */
	private static final class Rule {
		final String behavior;
		final String severity; // info | suspicious | high
		final String[] imports;

		Rule(String behavior, String severity, String... imports) {
			this.behavior = behavior;
			this.severity = severity;
			this.imports = imports;
		}
	}

	// Import-driven rules. A rule fires if ANY listed import symbol is present.
	private static final Rule[] IMPORT_RULES = {
			new Rule("anti-debug", "high", "ptrace"),
			new Rule("dynamic-code-loading", "suspicious", "dlopen", "dlsym", "dladdr", "dlmopen"),
			new Rule("self-modifying-or-unpacking", "high", "mprotect", "__clear_cache", "memfd_create"),
			new Rule("process-execution", "high", "system", "popen", "execve", "execv", "execl", "execlp", "fork", "vfork"),
			new Rule("networking", "suspicious", "socket", "connect", "getaddrinfo", "gethostbyname",
					"inet_addr", "inet_pton", "sendto", "recvfrom"),
			new Rule("tls-or-crypto", "info", "SSL_connect", "SSL_new", "SSL_write", "EVP_EncryptInit",
					"EVP_DecryptInit", "EVP_EncryptInit_ex", "AES_encrypt", "AES_set_encrypt_key",
					"RAND_bytes", "CCCrypt"),
			new Rule("raw-memory-mapping", "info", "mmap", "mmap64", "mremap"),
			new Rule("syscall-obfuscation", "suspicious", "syscall", "svc"),
	};

	// String-driven rules for capabilities with no dedicated import symbol (root/tamper detection is
	// implemented by reading files/paths, so the tell is a path/marker literal, not an import).
	private static final class StrRule {
		final String behavior;
		final String severity;
		final String[] markers;

		StrRule(String behavior, String severity, String... markers) {
			this.behavior = behavior;
			this.severity = severity;
			this.markers = markers;
		}
	}

	private static final StrRule[] STRING_RULES = {
			new StrRule("root-detection", "suspicious", "/system/bin/su", "/system/xbin/su", "/sbin/su",
					"which su", "magisk", "Superuser.apk", "supersu"),
			new StrRule("debugger-detection", "high", "TracerPid", "/proc/self/status", "/proc/self/wchan"),
			new StrRule("emulator-detection", "suspicious", "goldfish", "ranchu", "/dev/qemu_pipe",
					"generic_x86", "vbox86"),
			new StrRule("tamper-detection", "suspicious", "/proc/self/maps", "frida", "gum-js-loop",
					"xposed", "/data/local/tmp"),
	};

	/**
	 * @param imports the parsed {@code .dynsym} imported symbol names (undefined symbols)
	 * @param asciiStrings a newline-joined dump of the lib's printable strings (for marker rules)
	 * @return one entry per fired behavior: {@code {behavior, severity, evidence:[...]}}
	 */
	public static List<Map<String, Object>> classify(Set<String> imports, String asciiStrings) {
		List<Map<String, Object>> out = new ArrayList<>();
		if (imports != null) {
			for (Rule r : IMPORT_RULES) {
				List<String> hits = new ArrayList<>();
				for (String sym : r.imports) {
					if (imports.contains(sym)) {
						hits.add(sym);
					}
				}
				if (!hits.isEmpty()) {
					out.add(entry(r.behavior, r.severity, hits));
				}
			}
		}
		if (asciiStrings != null && !asciiStrings.isEmpty()) {
			String lower = asciiStrings.toLowerCase(java.util.Locale.ROOT);
			for (StrRule r : STRING_RULES) {
				List<String> hits = new ArrayList<>();
				for (String m : r.markers) {
					if (lower.contains(m.toLowerCase(java.util.Locale.ROOT))) {
						hits.add(m);
					}
				}
				if (!hits.isEmpty()) {
					out.add(entry(r.behavior, r.severity, hits));
				}
			}
		}
		return out;
	}

	private static Map<String, Object> entry(String behavior, String severity, List<String> evidence) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("behavior", behavior);
		m.put("severity", severity);
		m.put("evidence", evidence);
		return m;
	}
}
