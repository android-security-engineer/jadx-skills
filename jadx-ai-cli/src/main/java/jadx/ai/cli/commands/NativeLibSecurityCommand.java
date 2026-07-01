package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;
import jadx.api.ResourcesLoader;

/**
 * Security-checks native libraries (.so files) embedded in the APK. Absorbs the ELF binary
 * analysis from {@code droid-re-chain}'s {@code tools_static.py} (checksec: NX/PIE/RELRO/
 * canary, crypto constants, URL extraction, obfuscation detection). Pure Java implementation
 * — parses ELF headers and section headers directly, no external tools (readelf/nm) needed.
 * Native capability — reads jadx's resource model.
 */
@Command(name = "native-lib-security", description = "Security-check native .so libraries (ELF analysis)")
public class NativeLibSecurityCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum libraries to analyze", defaultValue = "50")
	protected int limit = 50;

	/** Cap bytes read per .so so a huge packed lib can't exhaust memory (64 MiB, as NativeLibsCommand). */
	private static final long MAX_LIB_BYTES = 67108864L;

	// Crypto constant signatures (absorbed from droid-re-chain tools_static.py)
	private static final byte[][] CRYPTO_SIGS = {
			{ 0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5 },     // AES S-box
			{ 0x52, 0x09, 0x6a, (byte) 0xd5, 0x30, 0x36, (byte) 0xa5, 0x38 },     // AES reverse S-box
			{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },                   // RC4 identity key schedule
			{ 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef }, // MD5 init
			{ 0x6a, 0x09, (byte) 0xe6, 0x67, (byte) 0xbb, 0x67, (byte) 0xae, (byte) 0x85 }, // SHA-256 init
	};
	private static final String[] CRYPTO_NAMES = {
			"AES_SBOX", "AES_RSBOX", "RC4_KEY_SCHEDULE", "MD5_INIT", "SHA256_INIT"
	};
	private static final String[] CRYPTO_DESCS = {
			"AES substitution box", "AES reverse S-box", "RC4 identity key schedule",
			"MD5 initial constants", "SHA-256 initial hash"
	};

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit")) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> libraries = new ArrayList<>();
		int highRiskCount = 0;

		for (ResourceFile res : decompiler.getResources()) {
			if (libraries.size() >= limit) {
				break;
			}
			if (res.getType() != ResourceType.LIB) {
				continue;
			}
			String name = res.getOriginalName();
			if (name == null || !name.toLowerCase(java.util.Locale.ROOT).endsWith(".so")) {
				continue;
			}

			byte[] data;
			try {
				data = readResourceBytes(res);
				if (data == null || data.length < 64) {
					continue;
				}
			} catch (Exception e) {
				continue;
			}

			// Verify ELF magic
			if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
				continue;
			}

			Map<String, Object> lib = analyzeElf(name, data);
			if (lib != null) {
				libraries.add(lib);
				boolean nx = Boolean.TRUE.equals(lib.get("nx"));
				boolean pie = Boolean.TRUE.equals(lib.get("pie"));
				boolean canary = Boolean.TRUE.equals(lib.get("canary"));
				if (!nx || !pie || !canary) {
					highRiskCount++;
				}
			}
		}

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("libraries", libraries);
		data.put("libraryCount", libraries.size());
		data.put("highRiskCount", highRiskCount);
		data.put("truncated", libraries.size() >= limit);
		return JsonOutput.ok(data);
	}

	private byte[] readResourceBytes(ResourceFile res) {
		// Read the .so's raw bytes straight from the APK zip entry via jadx's ResourcesLoader —
		// the same path NativeLibsCommand uses. (The old body returned null unconditionally, which
		// silently reduced every native-lib-security run to an empty result.)
		try {
			byte[] read = ResourcesLoader.decodeStream(res,
					(size, is) -> is.readNBytes((int) Math.min(MAX_LIB_BYTES, Integer.MAX_VALUE)));
			return read;
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * Parse ELF header and key security properties. Pure Java, no external deps.
	 * Absorbed from droid-re-chain's _read_elf_header and checksec.
	 */
	private Map<String, Object> analyzeElf(String name, byte[] data) {
		Map<String, Object> lib = new LinkedHashMap<>();
		lib.put("name", name);

		// ELF class (32-bit vs 64-bit)
		boolean is64 = data[4] == 2;
		lib.put("arch", getArch(data, is64));

		// PIE: check ELF type (ET_DYN=3 means PIE or shared lib, ET_EXEC=2 means no PIE)
		int eType = u16(data, 16);
		boolean pie = (eType == 3);
		lib.put("pie", pie);

		// NX: GCC enables NX by default on ARM; only disabled by explicit -z noexecstack
		// Check for GNU_STACK header with executable flag
		boolean nx = checkNx(data, is64);
		lib.put("nx", nx);

		// RELRO: GNU_RELRO program header presence is only PARTIAL relro. Full relro additionally
		// requires the loader to resolve every symbol up-front (BIND_NOW), which lives in the
		// .dynamic segment — so we parse it for ground truth rather than guess from a segment flag.
		boolean relro = checkRelro(data, is64);
		lib.put("relro", relro);

		// Ground-truth dynamic-segment parse: DT_NEEDED deps, SONAME, RUNPATH/RPATH, BIND_NOW, FORTIFY.
		jadx.ai.cli.util.ElfDynamicInfo dyn = jadx.ai.cli.util.ElfDynamicInfo.parse(data);
		lib.put("relroType", dyn.relroType(relro)); // none | partial | full (checksec semantics)
		lib.put("neededLibraries", dyn.needed);
		if (dyn.soname != null && !dyn.soname.isEmpty()) {
			lib.put("soname", dyn.soname);
		}
		if (dyn.runpath != null && !dyn.runpath.isEmpty()) {
			lib.put("runpath", dyn.runpath); // writable RUNPATH => library-hijack surface
		}
		if (dyn.rpath != null && !dyn.rpath.isEmpty()) {
			lib.put("rpath", dyn.rpath);
		}
		lib.put("fortifySourceFunctions", dyn.fortifyChkCount); // count of *_chk fortified imports

		// Ground-truth dynamic symbol table (nm -D). Survives strip, so it beats the string heuristic:
		// exportedCount/jniExports are the REAL native attack surface to cross-ref native-bridge-index.
		jadx.ai.cli.util.ElfSymbols syms = jadx.ai.cli.util.ElfSymbols.parse(data, 200);
		lib.put("exportedCount", syms.exportedCount);
		lib.put("importedCount", syms.importedCount);
		lib.put("exportedFunctions", syms.exported);
		lib.put("importedFunctions", syms.imported);
		lib.put("jniExports", syms.jniExports); // Java_* / JNI_OnLoad actually present in the .so

		// Stack canary: __stack_chk_fail present. Prefer the parsed .dynsym (exact) over a string grep,
		// falling back to the string scan when the symbol table couldn't be walked.
		boolean canary = syms.parsed
				? (syms.imported.contains("__stack_chk_fail") || syms.exported.contains("__stack_chk_fail")
						|| checkCanary(data))
				: checkCanary(data);
		lib.put("canary", canary);

		// Crypto constants
		List<Map<String, Object>> cryptoFound = new ArrayList<>();
		for (int i = 0; i < CRYPTO_SIGS.length; i++) {
			int offset = indexOf(data, CRYPTO_SIGS[i]);
			if (offset >= 0) {
				Map<String, Object> c = new LinkedHashMap<>();
				c.put("name", CRYPTO_NAMES[i]);
				c.put("description", CRYPTO_DESCS[i]);
				c.put("offset", "0x" + Integer.toHexString(offset));
				cryptoFound.add(c);
			}
		}
		lib.put("cryptoConstants", cryptoFound);

		// Extract hardcoded URLs/IPs (absorbed from droid-re-chain static_extract_urls)
		int urlCount = 0;
		StringBuilder urlSample = new StringBuilder();
		String ascii = extractAsciiStrings(data, 6);
		java.util.regex.Matcher urlMatcher = java.util.regex.Pattern
				.compile("https?://[^\\s\"'<>]+")
				.matcher(ascii);
		while (urlMatcher.find() && urlCount < 10) {
			if (urlSample.length() > 0) {
				urlSample.append(", ");
			}
			urlSample.append(urlMatcher.group());
			urlCount++;
		}
		lib.put("urlCount", urlCount);
		if (urlSample.length() > 0) {
			lib.put("urlSample", urlSample.toString());
		}

		// Obfuscation indicators (absorbed from droid-re-chain static_detect_obfuscation)
		List<String> obfuscationIndicators = new ArrayList<>();
		if (!hasTextSection(data, is64)) {
			obfuscationIndicators.add("missing .text section (stripped or packed)");
		}
		if (syms.parsed ? (syms.exportedCount == 0 && syms.importedCount == 0) : isSymbolStripped(data)) {
			obfuscationIndicators.add("empty dynamic symbol table (packed/obfuscated)");
		}
			// A lib that exposes JNI_OnLoad but exports no Java_* symbols registers its natives
			// dynamically via RegisterNatives — a common tactic to hide the native surface from static
			// cross-referencing against native-bridge-index's Java-declared native methods.
			if (syms.parsed && syms.jniExports.isEmpty() && syms.exported.contains("JNI_OnLoad")) {
				obfuscationIndicators.add("JNI methods registered dynamically (no exported Java_* symbols)");
			}
			lib.put("obfuscationIndicators", obfuscationIndicators);

		return lib;
	}

	private static String getArch(byte[] data, boolean is64) {
		int eMachine = u16(data, 18);
		if (is64) {
			if (eMachine == 183) {
				return "AArch64";
			}
			if (eMachine == 62) {
				return "x86_64";
			}
		} else {
			if (eMachine == 40) {
				return "ARM32";
			}
			if (eMachine == 3) {
				return "x86";
			}
		}
		return "unknown";
	}

	private static boolean checkNx(byte[] data, boolean is64) {
		// Default: NX is enabled on modern Android. Only disabled by GNU_STACK with E flag.
		long phOff = is64 ? u64(data, 32) : u32(data, 28);
		int phEntSize = is64 ? u16(data, 54) : u16(data, 42);
		int phNum = u16(data, is64 ? 56 : 44);

		for (int i = 0; i < phNum && i < 64; i++) {
			int off = (int)(phOff + i * phEntSize);
			if (off + phEntSize > data.length) {
				break;
			}
			long pType = u32(data, off);
			// PT_GNU_STACK = 0x6474e551
			if (pType == 0x6474e551L) {
				long pFlags = is64 ? u32(data, off + 4) : u32(data, off + 24);
				// PF_X = 1 (execute flag)
				return (pFlags & 1) == 0;
			}
		}
		// No GNU_STACK header → NX enabled (default)
		return true;
	}

	private static boolean checkRelro(byte[] data, boolean is64) {
		long phOff = is64 ? u64(data, 32) : u32(data, 28);
		int phEntSize = is64 ? u16(data, 54) : u16(data, 42);
		int phNum = u16(data, is64 ? 56 : 44);

		for (int i = 0; i < phNum && i < 64; i++) {
			int off = (int)(phOff + i * phEntSize);
			if (off + phEntSize > data.length) {
				break;
			}
			long pType = u32(data, off);
			// PT_GNU_RELRO = 0x6474e552
			if (pType == 0x6474e552L) {
				return true;
			}
		}
		return false;
	}

	private static boolean checkCanary(byte[] data) {
		// Look for __stack_chk_fail or __stack_chk_guard in the string table
		String ascii = extractAsciiStrings(data, 10);
		return ascii.contains("__stack_chk_fail") || ascii.contains("__stack_chk_guard")
				|| ascii.contains("__intel_security_cookie");
	}

	private static boolean hasTextSection(byte[] data, boolean is64) {
		// Quick check: if the file is too small for section headers, assume present
		if (data.length < 64) {
			return true;
		}
		// Look for ".text" in the binary
		String ascii = extractAsciiStrings(data, 5);
		return ascii.contains(".text");
	}

	private static boolean isSymbolStripped(byte[] data) {
		// Check for any common dynamic symbol names
		String ascii = extractAsciiStrings(data, 4);
		// If we find JNI_OnLoad or Java_ prefix, it's not fully stripped
		if (ascii.contains("JNI_OnLoad") || ascii.contains("Java_")) {
			return false;
		}
		// If we find common libc symbols, it's not stripped
		if (ascii.contains("malloc") || ascii.contains("free") || ascii.contains("printf")) {
			return false;
		}
		// Truly stripped: no recognizable symbol names
		return true;
	}

	private static String extractAsciiStrings(byte[] data, int minLen) {
		StringBuilder sb = new StringBuilder();
		StringBuilder current = new StringBuilder();
		for (byte b : data) {
			if (b >= 32 && b < 127) {
				current.append((char) b);
			} else {
				if (current.length() >= minLen) {
					sb.append(current).append('\n');
				}
				current.setLength(0);
			}
		}
		if (current.length() >= minLen) {
			sb.append(current);
		}
		return sb.toString();
	}

	private static int indexOf(byte[] data, byte[] pattern) {
		for (int i = 0; i <= data.length - pattern.length; i++) {
			boolean match = true;
			for (int j = 0; j < pattern.length; j++) {
				if (data[i + j] != pattern[j]) {
					match = false;
					break;
				}
			}
			if (match) {
				return i;
			}
		}
		return -1;
	}

	private static int u16(byte[] d, int off) {
		return (d[off] & 0xFF) | ((d[off + 1] & 0xFF) << 8);
	}

	private static long u32(byte[] d, int off) {
		return (d[off] & 0xFFL) | ((d[off + 1] & 0xFFL) << 8)
				| ((d[off + 2] & 0xFFL) << 16) | ((d[off + 3] & 0xFFL) << 24);
	}

	private static long u64(byte[] d, int off) {
		return u32(d, off) | (u32(d, off + 4) << 32);
	}

	@Override
	protected String getDaemonCommandName() {
		return "native-lib-security";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("limit", limit);
		return args;
	}
}
