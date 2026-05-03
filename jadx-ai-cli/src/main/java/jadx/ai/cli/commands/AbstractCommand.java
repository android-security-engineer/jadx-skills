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

	@Option(names = { "--use-imports" }, description = "Use import statements", defaultValue = "true")
	protected boolean useImports = true;

	@Option(names = { "--debug-info" }, description = "Include debug info in output", defaultValue = "true")
	protected boolean debugInfo = true;

	@Option(names = { "--inline-anonymous" }, description = "Inline anonymous classes", defaultValue = "true")
	protected boolean inlineAnonymousClasses = true;

	@Option(names = { "--inline-methods" }, description = "Inline methods", defaultValue = "true")
	protected boolean inlineMethods = true;

	@Option(names = { "--move-inner" }, description = "Move inner classes", defaultValue = "true")
	protected boolean moveInnerClasses = true;

	@Option(names = { "--extract-finally" }, description = "Extract finally blocks", defaultValue = "true")
	protected boolean extractFinally = true;

	@Option(names = { "--escape-unicode" }, description = "Escape unicode characters")
	protected boolean escapeUnicode;

	@Option(names = { "--replace-consts" }, description = "Replace constants", defaultValue = "true")
	protected boolean replaceConsts = true;

	@Option(names = { "--respect-bytecode-modifiers" }, description = "Respect bytecode access modifiers")
	protected boolean respectBytecodeAccModifiers;

	@Option(names = { "--deobf-min-length" }, description = "Minimum name length for deobfuscation", defaultValue = "0")
	protected int deobfMinLength;

	@Option(names = { "--deobf-max-length" }, description = "Maximum name length for deobfuscation")
	protected int deobfMaxLength = Integer.MAX_VALUE;

	@Option(names = { "--integer-format" }, description = "Integer format: AUTO, DEC, HEX, OCT", defaultValue = "AUTO")
	protected String integerFormat = "AUTO";

	@Option(names = { "--threads-count" }, description = "Number of processing threads", defaultValue = "-1")
	protected int threadsCount = -1;

	@Option(names = { "--class-filter" }, description = "Class name filter (regex)")
	protected String classFilter;

	@Option(names = { "--include-dependencies" }, description = "Include dependencies for filtered classes")
	protected boolean includeDependencies;

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
			args.setUseImports(useImports);
			args.setDebugInfo(debugInfo);
			args.setInlineAnonymousClasses(inlineAnonymousClasses);
			args.setInlineMethods(inlineMethods);
			args.setMoveInnerClasses(moveInnerClasses);
			args.setExtractFinally(extractFinally);
			args.setEscapeUnicode(escapeUnicode);
			args.setReplaceConsts(replaceConsts);
			args.setRespectBytecodeAccModifiers(respectBytecodeAccModifiers);
			args.setDeobfuscationMinLength(deobfMinLength);
			args.setDeobfuscationMaxLength(deobfMaxLength);
			args.setIntegerFormat(jadx.api.args.IntegerFormat.valueOf(integerFormat.toUpperCase()));
			if (threadsCount > 0) {
				args.setThreadsCount(threadsCount);
			}
			if (classFilter != null) {
				args.setClassFilter(s -> s.matches(classFilter));
			}
			args.setIncludeDependencies(includeDependencies);

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
