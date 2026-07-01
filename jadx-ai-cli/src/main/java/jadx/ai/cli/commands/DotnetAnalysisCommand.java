package jadx.ai.cli.commands;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;
import jadx.api.ResourcesLoader;

/**
 * Analyzes a Xamarin / .NET-for-Android (MAUI) APK by inspecting the bundled managed assemblies —
 * the layer where the real C#/IL application logic lives, invisible to a Java decompiler. Absorbs
 * the design idea from {@code pyxamstore} / {@code Xamarin.Android} unpackers (which parse the
 * AssemblyStore {@code assemblies.blob} and decompress the per-DLL {@code XALZ}/LZ4 wrapper before
 * handing the raw PE to a .NET decompiler) and reimplements the header-level triage natively over
 * jadx's resource API.
 *
 * <p>Why {@code framework-detect} does not cover this: it only matches resource <em>names</em>. This
 * command reads the actual bytes of each {@code assemblies/*.dll} (and the {@code assemblies.blob}
 * store) to answer the questions that decide the reversing path:</p>
 * <ul>
 *   <li>Are the assemblies stored as raw PE files (MZ magic) or wrapped/compressed with the Xamarin
 *       {@code XALZ} LZ4 header — i.e. do they need decompressing before ILSpy/dnSpy/dotpeek?</li>
 *   <li>Are they packed into a single {@code assemblies.blob} AssemblyStore (magic {@code XABA})?</li>
 *   <li>Which runtime flavor: classic Mono/Xamarin ({@code mscorlib.dll}) vs modern
 *       .NET 5+/MAUI ({@code System.Private.CoreLib.dll}) — read straight from the assembly list.</li>
 * </ul>
 *
 * <p>Header formats (little-endian). XALZ per-assembly wrapper: {@code "XALZ"} magic (4 bytes) +
 * {@code uint32 descriptorIndex} + {@code uint32 uncompressedLength}, then an LZ4 block.
 * AssemblyStore: {@code "XABA"} magic + {@code uint32 version} + {@code uint32 entryCount}.</p>
 */
@Command(name = "dotnet-analysis",
		description = "Analyze a Xamarin/.NET (MAUI) APK: enumerate managed assemblies, detect XALZ/LZ4 compression, AssemblyStore blob, and runtime flavor")
public class DotnetAnalysisCommand extends AbstractCommand {

	@Option(names = { "--limit" }, description = "Maximum assemblies to list", defaultValue = "500")
	protected int limit = 500;

	/** Only the first bytes of each assembly are needed to read its magic + uncompressed size. */
	private static final int HEAD_BYTES = 64;

	@Override
	protected void applyArgs(Map<String, Object> args) {
		if (args.containsKey("limit") && args.get("limit") != null) {
			this.limit = ((Number) args.get("limit")).intValue();
		}
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<Map<String, Object>> assemblies = new ArrayList<>();
		ResourceFile storeBlob = null;
		boolean hasMonodroidLib = false;
		boolean hasMonosgenLib = false;
		boolean hasXamarinAppLib = false;
		boolean hasDotnetRuntimeLib = false;
		boolean sawMscorlib = false;
		boolean sawCoreLib = false;
		boolean sawXalz = false;
		boolean sawRawPe = false;
		boolean sawAssemblyCSharp = false;
		boolean hasUnityManagedPath = false;
		int dllCount = 0;

		for (ResourceFile res : decompiler.getResources()) {
			String name = res.getOriginalName();
			if (name == null) {
				continue;
			}
			String norm = name.replace('\\', '/');
			String base = norm.substring(norm.lastIndexOf('/') + 1);

			if (norm.contains("libmonodroid.so")) {
				hasMonodroidLib = true;
			}
			if (norm.contains("libmonosgen")) {
				hasMonosgenLib = true;
			}
			if (norm.contains("libxamarin-app.so")) {
				hasXamarinAppLib = true;
			}
			// .NET 6+/MAUI ships the CoreCLR/Mono runtime as these.
			if (norm.contains("libSystem.Native.so") || norm.contains("libnet-android")
					|| norm.contains("libaot-") || norm.contains("libhostpolicy.so")) {
				hasDotnetRuntimeLib = true;
			}

			if (base.equalsIgnoreCase("assemblies.blob") || base.matches("(?i)assemblies\\.[a-z0-9_]+\\.blob")) {
				storeBlob = res;
				continue;
			}
			if (!base.toLowerCase(java.util.Locale.ROOT).endsWith(".dll")) {
				continue;
			}
			// Assembly names carry the runtime-flavor signal directly.
			if (base.equalsIgnoreCase("mscorlib.dll")) {
				sawMscorlib = true;
			}
			if (base.equalsIgnoreCase("System.Private.CoreLib.dll")) {
				sawCoreLib = true;
			}
			// Unity Mono (non-IL2CPP): the game logic ships as plain-IL Assembly-CSharp.dll under
			// assets/bin/Data/Managed/ — directly decompilable, no il2cpp dumping needed.
			if (norm.contains("bin/Data/Managed/")) {
				hasUnityManagedPath = true;
			}
			if (base.equalsIgnoreCase("Assembly-CSharp.dll")) {
				sawAssemblyCSharp = true;
			}

			dllCount++;
			if (assemblies.size() >= limit) {
				continue;
			}
			Map<String, Object> a = new LinkedHashMap<>();
			a.put("name", base);
			a.put("path", norm);
			byte[] head = readHead(res);
			if (head != null) {
				if (isXalz(head)) {
					a.put("format", "XALZ");
					a.put("compressed", true);
					long usize = xalzUncompressedSize(head);
					if (usize >= 0) {
						a.put("uncompressedSize", usize);
					}
					sawXalz = true;
				} else if (isPe(head)) {
					a.put("format", "PE");
					a.put("compressed", false);
					sawRawPe = true;
				} else {
					a.put("format", "unknown");
				}
			}
			assemblies.add(a);
		}

		String storeFormat = null;
		Integer storeEntryCount = null;
		if (storeBlob != null) {
			byte[] head = readHead(storeBlob);
			if (head != null && isAssemblyStore(head)) {
				storeFormat = "AssemblyStore(XABA)";
				storeEntryCount = readU32(head, 8) < 0 ? null : (int) readU32(head, 8);
			} else {
				storeFormat = "assemblies.blob";
			}
		}

		boolean isUnityMono = sawAssemblyCSharp || hasUnityManagedPath;
		boolean isDotnet = dllCount > 0 || storeBlob != null || hasMonodroidLib
				|| hasMonosgenLib || hasXamarinAppLib || hasDotnetRuntimeLib || isUnityMono;

		String flavor = runtimeFlavor(isUnityMono, sawCoreLib || hasDotnetRuntimeLib,
				sawMscorlib || hasMonodroidLib || hasMonosgenLib || hasXamarinAppLib, isDotnet);

		Map<String, Object> data = new LinkedHashMap<>();
		data.put("isDotnet", isDotnet);
		data.put("runtimeFlavor", flavor);
		data.put("hasMonodroidLib", hasMonodroidLib);
		data.put("hasMonosgenLib", hasMonosgenLib);
		data.put("hasXamarinAppLib", hasXamarinAppLib);
		data.put("hasDotnetRuntimeLib", hasDotnetRuntimeLib);
		data.put("assemblyCount", dllCount);
		data.put("assemblies", assemblies);
		if (storeFormat != null) {
			data.put("assemblyStore", storeFormat);
			if (storeEntryCount != null) {
				data.put("assemblyStoreEntryCount", storeEntryCount);
			}
		}
		data.put("xalzCompressed", sawXalz);
		data.put("rawPeAssemblies", sawRawPe);
		data.put("unityMono", isUnityMono);
		data.put("hasAssemblyCSharp", sawAssemblyCSharp);

		if (isDotnet) {
			List<String> notes = new ArrayList<>();
			notes.add(".NET/Xamarin app — real logic is C#/IL in the managed assemblies, not the Java shell");
			if (sawAssemblyCSharp) {
				notes.add("Unity Mono game: Assembly-CSharp.dll is plain IL — decompile directly with ILSpy/dnSpy (no il2cpp dumping; game logic/anti-cheat/IAP checks are fully readable)");
			} else if (isUnityMono) {
				notes.add("Unity Mono layout (bin/Data/Managed) — managed game assemblies are directly decompilable");
			}
			if (sawXalz) {
				notes.add("Assemblies are XALZ/LZ4-compressed — decompress (e.g. pyxamstore/xalz) before ILSpy/dnSpy");
			}
			if (storeFormat != null && storeFormat.startsWith("AssemblyStore")) {
				notes.add("Assemblies are packed in an AssemblyStore blob — unpack it first, then decompile each DLL");
			}
			if (sawRawPe) {
				notes.add("Raw PE assemblies present — extract from the APK and decompile directly with ILSpy/dnSpy/dotpeek");
			}
			data.put("notes", notes);
		}
		return JsonOutput.ok(data);
	}

	/**
	 * Runtime flavor by precedence. Unity Mono is checked first because a Unity game also ships
	 * {@code mscorlib.dll} (which would otherwise read as classic Xamarin) — the Unity layout is the
	 * more specific signal and must win.
	 */
	static String runtimeFlavor(boolean unityMono, boolean modernDotnet, boolean classicMono, boolean isDotnet) {
		if (unityMono) {
			return "Unity (Mono)";
		}
		if (modernDotnet) {
			return ".NET 5+ / MAUI";
		}
		if (classicMono) {
			return "classic Xamarin.Android (Mono)";
		}
		return isDotnet ? "unknown .NET" : "not .NET";
	}

	private static byte[] readHead(ResourceFile res) {
		try {
			return ResourcesLoader.decodeStream(res, (size, is) -> is.readNBytes(HEAD_BYTES));
		} catch (Exception e) {
			return null;
		}
	}

	/** True if the buffer begins with the ASCII bytes {@code magic} (e.g. {@code "XALZ"}). */
	static boolean hasMagic(byte[] data, String magic) {
		if (data == null || data.length < magic.length()) {
			return false;
		}
		for (int i = 0; i < magic.length(); i++) {
			if ((data[i] & 0xFF) != magic.charAt(i)) {
				return false;
			}
		}
		return true;
	}

	/** Xamarin per-assembly LZ4 wrapper: {@code "XALZ"} magic. */
	static boolean isXalz(byte[] data) {
		return hasMagic(data, "XALZ");
	}

	/** AssemblyStore blob: {@code "XABA"} magic. */
	static boolean isAssemblyStore(byte[] data) {
		return hasMagic(data, "XABA");
	}

	/** A raw Windows PE / .NET assembly starts with the DOS {@code "MZ"} stub. */
	static boolean isPe(byte[] data) {
		return hasMagic(data, "MZ");
	}

	/** XALZ uncompressed length: {@code uint32} little-endian at offset 8. -1 if out of range. */
	static long xalzUncompressedSize(byte[] data) {
		return readU32(data, 8);
	}

	/** Read an unsigned 32-bit little-endian int at {@code off}; -1 if out of range. */
	private static long readU32(byte[] data, int off) {
		if (data == null || off < 0 || off + 4 > data.length) {
			return -1;
		}
		return ByteBuffer.wrap(data, off, 4).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xFFFFFFFFL;
	}

	@Override
	protected String getDaemonCommandName() {
		return "dotnet-analysis";
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new LinkedHashMap<>();
		args.put("limit", limit);
		return args;
	}
}
