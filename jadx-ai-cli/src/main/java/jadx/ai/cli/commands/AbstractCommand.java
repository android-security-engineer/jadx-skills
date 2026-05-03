package jadx.ai.cli.commands;

import java.io.File;
import java.io.PrintStream;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.CommentsLevel;
import jadx.api.DecompilationMode;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.impl.NoOpCodeCache;
import jadx.api.usage.impl.EmptyUsageInfoCache;

public abstract class AbstractCommand implements Runnable {

	@Parameters(index = "0", description = "Input file (APK, DEX, JAR, AAR, or class)")
	protected File inputFile;

	@Option(names = { "--format" }, description = "Output format: json (default) or plain", defaultValue = "json")
	protected String format;

	@Option(
			names = { "--decompilation-mode" }, description = "Decompilation mode: AUTO, RESTRUCTURE, SIMPLE, FALLBACK",
			defaultValue = "AUTO"
	)
	protected String decompilationMode;

	@Option(names = { "--show-bad-code" }, description = "Show inconsistent code (bad code)")
	protected boolean showBadCode;

	@Option(names = { "--deobfuscation" }, description = "Enable deobfuscation")
	protected boolean deobfuscation;

	@Option(
			names = { "--comments-level" }, description = "Comments level: NONE, USER_ONLY, ERROR, WARN, INFO, DEBUG", defaultValue = "WARN"
	)
	protected String commentsLevel;

	@Option(names = { "--include-resources" }, description = "Include resources (not skip them)")
	protected boolean includeResources;

	private static final Gson GSON = new GsonBuilder()
			.setPrettyPrinting()
			.disableHtmlEscaping()
			.create();

	@Override
	public void run() {
		JadxDecompiler decompiler = null;
		try {
			JadxArgs args = new JadxArgs();
			args.setInputFile(inputFile);
			args.setSkipResources(!includeResources);
			args.setShowInconsistentCode(showBadCode);
			args.setDeobfuscationOn(deobfuscation);
			args.setDecompilationMode(DecompilationMode.valueOf(decompilationMode.toUpperCase()));
			args.setCommentsLevel(CommentsLevel.valueOf(commentsLevel.toUpperCase()));
			args.setCodeCache(new NoOpCodeCache());
			args.setUsageInfoCache(new EmptyUsageInfoCache());

			decompiler = new JadxDecompiler(args);
			decompiler.load();

			Object result = execute(decompiler);
			outputResult(result, System.out);
		} catch (Exception e) {
			JsonOutput error = JsonOutput.error(e.getClass().getSimpleName(), e.getMessage());
			outputResult(error, System.err);
		} finally {
			if (decompiler != null) {
				decompiler.close();
			}
		}
	}

	protected abstract Object execute(JadxDecompiler decompiler) throws Exception;

	protected void outputResult(Object data, PrintStream out) {
		if ("json".equals(format)) {
			out.println(GSON.toJson(data));
		} else {
			out.println(data);
		}
	}
}
