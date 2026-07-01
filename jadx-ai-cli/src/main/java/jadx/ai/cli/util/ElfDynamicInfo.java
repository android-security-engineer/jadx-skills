package jadx.ai.cli.util;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Ground-truth parser for an ELF's {@code PT_DYNAMIC} segment — the {@code readelf -d} / {@code nm -D}
 * / {@code checksec} data that string-heuristics cannot recover. Given the raw bytes of a
 * {@code lib/<abi>/*.so}, walks the dynamic array (resolving names through {@code DT_STRTAB} via the
 * {@code PT_LOAD} vaddr→file-offset map) and surfaces:
 *
 * <ul>
 *   <li>{@code needed} — the {@code DT_NEEDED} shared-library dependencies (does this .so link its own
 *       OpenSSL? curl? only libc/liblog?) — the single most useful native-triage fact after arch.</li>
 *   <li>{@code soname} — the {@code DT_SONAME} the loader keys on.</li>
 *   <li>{@code runpath}/{@code rpath} — {@code DT_RUNPATH}/{@code DT_RPATH}; a writable rpath is a
 *       library-hijack surface.</li>
 *   <li>{@code bindNow} — {@code DT_BIND_NOW} or {@code DT_FLAGS &amp; DF_BIND_NOW} or
 *       {@code DT_FLAGS_1 &amp; DF_1_NOW}; combined with a GNU_RELRO segment this is the Partial-vs-Full
 *       RELRO distinction {@code checksec} reports.</li>
 *   <li>{@code fortifyChkCount} — number of distinct {@code *_chk} fortified libc imports in
 *       {@code .dynstr} (FORTIFY_SOURCE evidence).</li>
 * </ul>
 *
 * Pure Java, little-endian (all Android ABIs are LE), never throws — returns whatever it could parse
 * with {@link #parsed} indicating whether a {@code PT_DYNAMIC} segment was found and walked.
 */
public final class ElfDynamicInfo {

	// Dynamic-array tags (Elf*_Dyn d_tag).
	private static final long DT_NULL = 0;
	private static final long DT_NEEDED = 1;
	private static final long DT_STRTAB = 5;
	private static final long DT_STRSZ = 10;
	private static final long DT_SONAME = 14;
	private static final long DT_RPATH = 15;
	private static final long DT_RUNPATH = 29;
	private static final long DT_FLAGS = 30;
	private static final long DT_BIND_NOW = 24;
	private static final long DT_FLAGS_1 = 0x6ffffffbL;
	private static final long DF_BIND_NOW = 0x8;
	private static final long DF_1_NOW = 0x1;

	public boolean parsed;
	public boolean is64;
	public boolean bindNow;
	public String soname;
	public String runpath;
	public String rpath;
	public final List<String> needed = new ArrayList<>();
	public int fortifyChkCount;

	private ElfDynamicInfo() {
	}

	/** Parse the dynamic segment; always returns a non-null object (check {@link #parsed}). */
	public static ElfDynamicInfo parse(byte[] d) {
		ElfDynamicInfo out = new ElfDynamicInfo();
		try {
			if (d == null || d.length < 64 || d[0] != 0x7F || d[1] != 'E' || d[2] != 'L' || d[3] != 'F') {
				return out;
			}
			boolean is64 = d[4] == 2;
			out.is64 = is64;

			long phOff = is64 ? u64(d, 32) : u32(d, 28);
			int phEntSize = u16(d, is64 ? 54 : 42);
			int phNum = u16(d, is64 ? 56 : 44);

			// First pass over program headers: locate PT_DYNAMIC and collect PT_LOAD segments so
			// we can translate the virtual addresses stored in the dynamic array to file offsets.
			long dynOff = -1;
			long dynSize = 0;
			List<long[]> loads = new ArrayList<>(); // {vaddr, fileOff, filesz}
			for (int i = 0; i < phNum && i < 256; i++) {
				long off = phOff + (long) i * phEntSize;
				if (off < 0 || off + phEntSize > d.length) {
					break;
				}
				long pType = u32(d, (int) off);
				long pOffset;
				long pVaddr;
				long pFilesz;
				if (is64) {
					pOffset = u64(d, (int) off + 8);
					pVaddr = u64(d, (int) off + 16);
					pFilesz = u64(d, (int) off + 32);
				} else {
					pOffset = u32(d, (int) off + 4);
					pVaddr = u32(d, (int) off + 8);
					pFilesz = u32(d, (int) off + 16);
				}
				if (pType == 1) { // PT_LOAD
					loads.add(new long[] { pVaddr, pOffset, pFilesz });
				} else if (pType == 2) { // PT_DYNAMIC
					dynOff = pOffset;
					dynSize = pFilesz;
				}
			}
			if (dynOff < 0) {
				return out;
			}

			// Walk the dynamic array collecting the raw d_val for the tags we care about. STRTAB is a
			// vaddr; we resolve names in a second pass once we know where the string table lands.
			long strtabVaddr = -1;
			long strsz = 0;
			long flags = 0;
			long flags1 = 0;
			boolean bindNowTag = false;
			List<Long> neededOffsets = new ArrayList<>();
			long sonameOff = -1;
			long runpathOff = -1;
			long rpathOff = -1;

			int entSize = is64 ? 16 : 8;
			long maxEntries = dynSize > 0 ? dynSize / entSize : 4096;
			for (long i = 0; i < maxEntries && i < 8192; i++) {
				long e = dynOff + i * entSize;
				if (e < 0 || e + entSize > d.length) {
					break;
				}
				long tag;
				long val;
				if (is64) {
					tag = u64(d, (int) e);
					val = u64(d, (int) e + 8);
				} else {
					tag = u32(d, (int) e);
					val = u32(d, (int) e + 4);
				}
				if (tag == DT_NULL) {
					break;
				}
				if (tag == DT_STRTAB) {
					strtabVaddr = val;
				} else if (tag == DT_STRSZ) {
					strsz = val;
				} else if (tag == DT_NEEDED) {
					neededOffsets.add(val);
				} else if (tag == DT_SONAME) {
					sonameOff = val;
				} else if (tag == DT_RUNPATH) {
					runpathOff = val;
				} else if (tag == DT_RPATH) {
					rpathOff = val;
				} else if (tag == DT_FLAGS) {
					flags = val;
				} else if (tag == DT_FLAGS_1) {
					flags1 = val;
				} else if (tag == DT_BIND_NOW) {
					bindNowTag = true;
				}
			}
			out.parsed = true;
			out.bindNow = bindNowTag || (flags & DF_BIND_NOW) != 0 || (flags1 & DF_1_NOW) != 0;

			// Resolve DT_STRTAB vaddr → file offset via the PT_LOAD map, then read NUL-terminated names.
			long strtabFileOff = vaddrToFileOff(strtabVaddr, loads);
			if (strtabFileOff >= 0) {
				for (long nOff : neededOffsets) {
					String s = cstr(d, strtabFileOff + nOff);
					if (s != null && !s.isEmpty()) {
						out.needed.add(s);
					}
				}
				out.soname = sonameOff >= 0 ? cstr(d, strtabFileOff + sonameOff) : null;
				out.runpath = runpathOff >= 0 ? cstr(d, strtabFileOff + runpathOff) : null;
				out.rpath = rpathOff >= 0 ? cstr(d, strtabFileOff + rpathOff) : null;
				out.fortifyChkCount = countChk(d, strtabFileOff, strsz);
			}
		} catch (Exception ignored) {
			// best-effort: return whatever we managed to parse
		}
		return out;
	}

	/** Partial vs Full RELRO in checksec's terms, given whether a GNU_RELRO segment is present. */
	public String relroType(boolean hasRelroSegment) {
		if (!hasRelroSegment) {
			return "none";
		}
		return bindNow ? "full" : "partial";
	}

	private static long vaddrToFileOff(long vaddr, List<long[]> loads) {
		if (vaddr < 0) {
			return -1;
		}
		for (long[] seg : loads) {
			long v = seg[0];
			long fo = seg[1];
			long sz = seg[2];
			if (vaddr >= v && vaddr < v + sz) {
				return fo + (vaddr - v);
			}
		}
		return -1;
	}

	/** Scan the {@code .dynstr} region for distinct fortified {@code *_chk} import names. */
	private static int countChk(byte[] d, long strOff, long strsz) {
		long end = strsz > 0 ? Math.min(d.length, strOff + strsz) : d.length;
		if (strOff < 0 || strOff >= d.length) {
			return 0;
		}
		Set<String> chk = new LinkedHashSet<>();
		int i = (int) strOff;
		StringBuilder cur = new StringBuilder();
		while (i < end) {
			byte b = d[i++];
			if (b == 0) {
				String s = cur.toString();
				if (s.endsWith("_chk") && s.length() > 4) {
					chk.add(s);
				}
				cur.setLength(0);
			} else if (b >= 32 && b < 127) {
				cur.append((char) b);
			} else {
				cur.setLength(0);
			}
		}
		return chk.size();
	}

	private static String cstr(byte[] d, long off) {
		if (off < 0 || off >= d.length) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		for (int i = (int) off; i < d.length && d[i] != 0; i++) {
			int c = d[i] & 0xFF;
			if (c < 32 || c > 126) {
				break;
			}
			sb.append((char) c);
			if (sb.length() > 4096) {
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
