package jadx.ai.cli.cache;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.ai.cli.cache.disk.BufferCodeCache;
import jadx.ai.cli.cache.disk.DiskCodeCache;
import jadx.api.JadxDecompiler;
import jadx.api.plugins.pass.JadxPassInfo;
import jadx.api.plugins.pass.impl.SimpleJadxPassInfo;
import jadx.api.plugins.pass.types.JadxPreparePass;
import jadx.core.dex.nodes.RootNode;

/**
 * Wires an on-disk decompiled-code cache into a headless {@link JadxDecompiler}.
 *
 * <p>
 * jadx keeps every decompiled class as a String in {@code InMemoryCodeCache} by default, which is the
 * single largest memory consumer for large apps. jadx-gui already ships a battle-tested on-disk cache
 * ({@code jadx.gui.cache.code.disk.DiskCodeCache}); the classes under {@link jadx.ai.cli.cache.disk} are
 * a verbatim port of it with the package renamed. This helper installs that cache for the CLI/daemon so
 * decompiled sources spill to a sibling {@code <input>.jadx.cache/} directory instead of staying resident,
 * and are reused across process invocations (keyed by an input-file hash inside {@code DiskCodeCache}).
 * </p>
 */
public final class CacheSupport {
	private static final Logger LOG = LoggerFactory.getLogger(CacheSupport.class);

	public enum Mode {
		MEMORY,
		DISK
	}

	private CacheSupport() {
	}

	public static Mode parseMode(String value) {
		if (value == null || value.isEmpty()) {
			return Mode.MEMORY;
		}
		return Mode.valueOf(value.trim().toUpperCase());
	}

	/**
	 * Resolve the per-input cache directory: a {@code <name>.jadx.cache} folder placed next to the input
	 * file. Mirrors jadx-gui's "local cache" layout so a GUI and CLI pointed at the same file can share it.
	 */
	public static Path resolveCacheDir(File inputFile) {
		Path input = inputFile.toPath().toAbsolutePath().normalize();
		String name = input.getFileName().toString();
		int dot = name.lastIndexOf('.');
		String base = dot > 0 ? name.substring(0, dot) : name;
		Path parent = input.getParent();
		if (parent == null) {
			parent = Paths.get(".").toAbsolutePath().normalize();
		}
		return parent.resolve(base + ".jadx.cache");
	}

	/**
	 * If {@code mode == DISK}, register a prepare-pass that swaps the in-memory code cache for a
	 * buffered on-disk cache. The pass runs after classes are loaded (so class ids are stable) but
	 * before decompilation, exactly like jadx-gui's {@code registerCodeCache}.
	 */
	public static void install(JadxDecompiler decompiler, Mode mode, File inputFile) {
		if (mode != Mode.DISK || inputFile == null) {
			return;
		}
		Path cacheDir = resolveCacheDir(inputFile);
		decompiler.addCustomPass(new JadxPreparePass() {
			@Override
			public JadxPassInfo getInfo() {
				return new SimpleJadxPassInfo("AiCliDiskCacheInit");
			}

			@Override
			public void init(RootNode root) {
				try {
					DiskCodeCache diskCache = new DiskCodeCache(root, cacheDir);
					root.getArgs().setCodeCache(new BufferCodeCache(diskCache));
					LOG.info("Disk code cache enabled at {}", cacheDir);
				} catch (Exception e) {
					LOG.warn("Failed to enable disk code cache, falling back to memory", e);
				}
			}
		});
	}
}
