package jadx.ai.cli.util;

import java.util.ArrayList;
import java.util.List;

/**
 * Ground-truth {@code nm -D} for an Android {@code .so}: parses the {@code .dynsym} dynamic symbol
 * table (located via ELF section headers, its string names via the linked {@code .dynstr}) to list
 * the REAL exported and imported functions — not the {@code strings}-heuristic guess
 * ({@code native-libs} greps text for {@code Java_}/{@code JNI_OnLoad}) that misses renamed symbols
 * and false-positives on unrelated string data.
 *
 * <p>Crucially {@code .dynsym} survives {@code strip} (dynamic symbols are required for linking; only
 * {@code .symtab} is removed), so this works on release libs where the string heuristic is blind.
 * The exported {@code Java_*} / {@code JNI_OnLoad} set is the actual native attack surface to
 * cross-reference against {@code native-bridge-index}'s Java-declared {@code native} methods: a
 * method declared in Java but ABSENT from the exports is registered dynamically via
 * {@code RegisterNatives} (a common hiding/obfuscation tactic worth flagging).
 *
 * Pure Java, little-endian, never throws — {@link #parsed} indicates whether a {@code .dynsym} was
 * found and walked.
 */
public final class ElfSymbols {

	private static final int SHT_DYNSYM = 11;
	private static final int STB_LOCAL = 0;
	private static final int STT_FUNC = 2;
	private static final int SHN_UNDEF = 0;

	public boolean parsed;
	public boolean is64;
	/** Defined, non-local symbols (exports). */
	public final List<String> exported = new ArrayList<>();
	/** Undefined symbols the lib imports from its DT_NEEDED deps. */
	public final List<String> imported = new ArrayList<>();
	/** Exported JNI entry points ({@code Java_*}, {@code JNI_OnLoad}/{@code JNI_OnUnload}). */
	public final List<String> jniExports = new ArrayList<>();
	public int exportedCount;
	public int importedCount;

	private ElfSymbols() {
	}

	/**
	 * @param cap max names to collect per list (keeps output bounded on huge libs); counts are exact.
	 */
	public static ElfSymbols parse(byte[] d, int cap) {
		ElfSymbols out = new ElfSymbols();
		try {
			if (d == null || d.length < 64 || d[0] != 0x7F || d[1] != 'E' || d[2] != 'L' || d[3] != 'F') {
				return out;
			}
			boolean is64 = d[4] == 2;
			out.is64 = is64;

			long shOff = is64 ? u64(d, 40) : u32(d, 32);
			int shEntSize = u16(d, is64 ? 58 : 46);
			int shNum = u16(d, is64 ? 60 : 48);
			if (shOff <= 0 || shEntSize <= 0 || shNum <= 0) {
				return out; // section headers stripped entirely (rare) — nothing to parse
			}

			// Locate the .dynsym section and, via its sh_link, the .dynstr it names symbols from.
			long symOff = -1;
			long symSize = 0;
			long symEnt = 0;
			int strSecIdx = -1;
			for (int i = 0; i < shNum && i < 4096; i++) {
				long sh = shOff + (long) i * shEntSize;
				if (sh < 0 || sh + shEntSize > d.length) {
					break;
				}
				long type = u32(d, (int) sh + 4);
				if (type == SHT_DYNSYM) {
					if (is64) {
						symOff = u64(d, (int) sh + 24);
						symSize = u64(d, (int) sh + 32);
						strSecIdx = (int) u32(d, (int) sh + 40); // sh_link
						symEnt = u64(d, (int) sh + 56);
					} else {
						symOff = u32(d, (int) sh + 16);
						symSize = u32(d, (int) sh + 20);
						strSecIdx = (int) u32(d, (int) sh + 24);
						symEnt = u32(d, (int) sh + 36);
					}
					break;
				}
			}
			if (symOff < 0 || symEnt <= 0 || strSecIdx < 0 || strSecIdx >= shNum) {
				return out;
			}

			// Resolve the linked string table's file offset.
			long strShdr = shOff + (long) strSecIdx * shEntSize;
			if (strShdr < 0 || strShdr + shEntSize > d.length) {
				return out;
			}
			long strOff = is64 ? u64(d, (int) strShdr + 24) : u32(d, (int) strShdr + 16);
			long strSize = is64 ? u64(d, (int) strShdr + 32) : u32(d, (int) strShdr + 20);

			long count = symSize / symEnt;
			for (long i = 0; i < count && i < 200000; i++) {
				long s = symOff + i * symEnt;
				if (s < 0 || s + symEnt > d.length) {
					break;
				}
				long stName;
				int info;
				int shndx;
				if (is64) {
					stName = u32(d, (int) s);        // st_name
					info = d[(int) s + 4] & 0xFF;     // st_info
					shndx = u16(d, (int) s + 6);      // st_shndx
				} else {
					stName = u32(d, (int) s);         // st_name
					info = d[(int) s + 12] & 0xFF;    // st_info
					shndx = u16(d, (int) s + 14);     // st_shndx
				}
				int bind = info >> 4;
				int stype = info & 0xF;
				if (stName == 0) {
					continue;
				}
				String name = cstr(d, strOff, strSize, stName);
				if (name == null || name.isEmpty()) {
					continue;
				}
				boolean undefined = shndx == SHN_UNDEF;
				if (undefined) {
					out.importedCount++;
					if (out.imported.size() < cap) {
						out.imported.add(name);
					}
				} else if (bind != STB_LOCAL) {
					out.exportedCount++;
					if (out.exported.size() < cap) {
						out.exported.add(name);
					}
					boolean jni = name.startsWith("Java_") || name.equals("JNI_OnLoad")
							|| name.equals("JNI_OnUnload");
					if (jni && (stype == STT_FUNC || stype == 0) && out.jniExports.size() < cap) {
						out.jniExports.add(name);
					}
				}
			}
			out.parsed = true;
		} catch (Exception ignored) {
			// best-effort
		}
		return out;
	}

	private static String cstr(byte[] d, long base, long size, long idx) {
		if (base < 0 || idx < 0) {
			return null;
		}
		long start = base + idx;
		long limit = size > 0 ? Math.min(d.length, base + size) : d.length;
		if (start < 0 || start >= limit) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		for (long i = start; i < limit && d[(int) i] != 0; i++) {
			int c = d[(int) i] & 0xFF;
			if (c < 32 || c > 126) {
				break;
			}
			sb.append((char) c);
			if (sb.length() > 2048) {
				break;
			}
		}
		return sb.toString();
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
}
