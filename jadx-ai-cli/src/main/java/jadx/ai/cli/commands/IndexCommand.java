package jadx.ai.cli.commands;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import jadx.ai.cli.cache.CacheSupport;
import jadx.ai.cli.index.SymbolIndexStore;
import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;

/**
 * Build, inspect and clear the on-disk symbol index that backs {@code search --use-index}.
 *
 * <p>
 * The index persists class/method/field (and optionally string-literal) symbols to flat TSV files
 * under {@code <input>.jadx.cache/symbols/}, keyed by an input fingerprint. Once built, symbol searches
 * can be answered by streaming those files with constant memory and without loading the decompiler —
 * directly serving the goal of lower resource usage for repeated headless queries.
 * </p>
 */
@Command(name = "index", description = "Manage the on-disk symbol index (build/status/clear) used by `search --use-index`")
public class IndexCommand extends AbstractCommand {

	@Parameters(index = "1", arity = "0..1", description = "Action: build, status (default), or clear", defaultValue = "status")
	protected String action = "status";

	@Option(
			names = { "--with-strings" },
			description = "Also index string literals (requires decompiling every class; slower to build). "
					+ "Combine with --cache-mode DISK to reuse decompiled code across runs."
	)
	protected boolean withStrings;

	@Override
	protected boolean requiresDecompiler() {
		// Only `build` needs the loaded decompiler to enumerate symbols; status/clear are pure disk ops.
		return "build".equalsIgnoreCase(action == null ? "" : action.trim());
	}

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (inputFile == null) {
			return JsonOutput.error("MissingInput", "Input file is required for index operations");
		}
		SymbolIndexStore store = new SymbolIndexStore(CacheSupport.resolveCacheDir(inputFile), inputFile);
		String act = action == null ? "status" : action.trim().toLowerCase();
		switch (act) {
			case "build":
				return doBuild(store, decompiler);
			case "status":
				return doStatus(store);
			case "clear":
				return doClear(store);
			default:
				return JsonOutput.error("InvalidAction", "Unknown action: " + act + ". Use: build, status, clear");
		}
	}

	private Object doBuild(SymbolIndexStore store, JadxDecompiler decompiler) throws Exception {
		SymbolIndexStore.Stats stats = store.build(decompiler, withStrings);
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("status", "built");
		out.put("dir", store.getDir().toString());
		out.put("withStrings", withStrings);
		out.put("classes", stats.classes);
		out.put("methods", stats.methods);
		out.put("fields", stats.fields);
		out.put("strings", stats.strings);
		out.put("buildMillis", stats.buildMillis);
		return out;
	}

	private Object doStatus(SymbolIndexStore store) throws Exception {
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("dir", store.getDir().toString());
		out.put("exists", store.exists());
		out.put("valid", store.isValid());
		if (store.exists()) {
			Properties meta = store.readMeta();
			out.put("hasStrings", Boolean.parseBoolean(meta.getProperty("hasStrings", "false")));
			out.put("classes", meta.getProperty("classes"));
			out.put("methods", meta.getProperty("methods"));
			out.put("fields", meta.getProperty("fields"));
			out.put("strings", meta.getProperty("strings"));
			out.put("jadxVersion", meta.getProperty("jadxVersion"));
			out.put("formatVersion", meta.getProperty("formatVersion"));
			out.put("builtAtMs", meta.getProperty("builtAtMs"));
			if (!store.isValid()) {
				out.put("hint", "Index is stale (input changed or format bumped); run `index build` to refresh");
			}
		} else {
			out.put("hint", "No index yet; run `index build [--with-strings]` to create one");
		}
		return out;
	}

	private Object doClear(SymbolIndexStore store) throws Exception {
		boolean existed = store.exists();
		store.clear();
		Map<String, Object> out = new LinkedHashMap<>();
		out.put("status", existed ? "cleared" : "nothing-to-clear");
		out.put("dir", store.getDir().toString());
		return out;
	}
}
