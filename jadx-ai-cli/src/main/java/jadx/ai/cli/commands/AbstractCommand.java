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
	@Option(names = { "--insert-debug-lines" }, description = "Insert debug line numbers into code")
	protected boolean insertDebugLines;

	@Option(names = { "--allow-inline-kotlin-lambda" }, description = "Allow inline Kotlin lambda", defaultValue = "true")
	protected boolean allowInlineKotlinLambda = true;

	@Option(names = { "--restore-switch-over-string" }, description = "Restore switch over string", defaultValue = "true")
	protected boolean restoreSwitchOverString = true;

	@Option(names = { "--skip-xml-pretty-print" }, description = "Skip XML pretty printing")
	protected boolean skipXmlPrettyPrint;

	@Option(names = { "--rename-case-sensitive" }, description = "Rename case sensitive", defaultValue = "true")
	protected boolean renameCaseSensitive = true;

	@Option(names = { "--rename-valid" }, description = "Rename to valid identifiers", defaultValue = "true")
	protected boolean renameValid = true;

	@Option(names = { "--rename-printable" }, description = "Rename to printable names", defaultValue = "true")
	protected boolean renamePrintable = true;

	@Option(names = { "--use-source-name-as-alias" }, description = "Use source name as class name alias: NO, YES, IF_NECESSARY")
	protected String useSourceNameAsAlias;

	@Option(names = { "--source-name-repeat-limit" }, description = "Source name repeat limit", defaultValue = "10")
	protected int sourceNameRepeatLimit = 10;

	@Option(names = { "--resource-name-source" }, description = "Resource name source: AUTO, ORIG, DEOBF", defaultValue = "AUTO")
	protected String resourceNameSource = "AUTO";

	@Option(
			names = { "--use-kotlin-methods-for-var-names" },
			description = "Use Kotlin methods for var names: DISABLE, APPLY, APPLY_AND_HIDE", defaultValue = "APPLY"
	)
	protected String useKotlinMethodsForVarNames = "APPLY";

	@Option(names = { "--use-dx-input" }, description = "Use DX input instead of java-input")
	protected boolean useDxInput;

	@Option(names = { "--user-renames-mappings-path" }, description = "Path to user renames mappings file")
	protected String userRenamesMappingsPath;

	@Option(
			names = { "--user-renames-mappings-mode" },
			description = "User renames mappings mode: IGNORE, READ, READ_AND_APPLY, READ_APPLY_AND_SAVE", defaultValue = "IGNORE"
	)
	protected String userRenamesMappingsMode = "IGNORE";

	@Option(names = { "--deobf-whitelist" }, description = "Deobfuscation whitelist (comma-separated class/package names ending with .*)")
	protected String deobfWhitelist;

	@Option(names = { "--export-gradle-type" }, description = "Export as Gradle project: AUTO, ANDROID_APP, ANDROID_LIBRARY, SIMPLE_JAVA")
	protected String exportGradleType;

	@Option(names = { "--generated-renames-mapping-file" }, description = "Output file for generated renames mapping")
	protected String generatedRenamesMappingFile;

	@Option(names = { "--disabled-passes" }, description = "Disabled passes (comma-separated pass names)")
	protected String disabledPasses;

	@Option(names = { "--plugin-options" }, description = "Plugin options (key=value pairs, comma-separated)")
	protected String pluginOptionsStr;

	@Option(names = { "--disabled-plugins" }, description = "Disabled plugins (comma-separated plugin IDs)")
	protected String disabledPluginsStr;

	@Option(
			names = { "--security-flags" },
			description = "Security flags: VERIFY_APP_PACKAGE, SECURE_XML_PARSER, SECURE_ZIP_READER (comma-separated, default: all)"
	)
	protected String securityFlagsStr;

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
			args.setInsertDebugLines(insertDebugLines);
			args.setAllowInlineKotlinLambda(allowInlineKotlinLambda);
			args.setRestoreSwitchOverString(restoreSwitchOverString);
			args.setSkipXmlPrettyPrint(skipXmlPrettyPrint);
			args.setRenameCaseSensitive(renameCaseSensitive);
			args.setRenameValid(renameValid);
			args.setRenamePrintable(renamePrintable);
			if (useSourceNameAsAlias != null) {
				args.setUseSourceNameAsClassNameAlias(
						jadx.api.args.UseSourceNameAsClassNameAlias.valueOf(useSourceNameAsAlias.toUpperCase()));
			}
			args.setSourceNameRepeatLimit(sourceNameRepeatLimit);
			args.setResourceNameSource(
					jadx.api.args.ResourceNameSource.valueOf(resourceNameSource.toUpperCase()));
			args.setUseKotlinMethodsForVarNames(
					jadx.api.JadxArgs.UseKotlinMethodsForVarNames.valueOf(useKotlinMethodsForVarNames.toUpperCase()));
			args.setUseDxInput(useDxInput);
			if (securityFlagsStr != null && !securityFlagsStr.isEmpty()) {
				java.util.Set<jadx.api.security.JadxSecurityFlag> flags = new java.util.HashSet<>();
				for (String flag : securityFlagsStr.split(",")) {
					flags.add(jadx.api.security.JadxSecurityFlag.valueOf(flag.trim().toUpperCase()));
				}
				args.setSecurity(new jadx.api.security.impl.JadxSecurity(flags));
			}
			if (userRenamesMappingsPath != null) {
				args.setUserRenamesMappingsPath(java.nio.file.Paths.get(userRenamesMappingsPath));
			}
			args.setUserRenamesMappingsMode(
					jadx.api.args.UserRenamesMappingsMode.valueOf(userRenamesMappingsMode.toUpperCase()));
			if (deobfWhitelist != null) {
				args.setDeobfuscationWhitelist(java.util.Arrays.asList(deobfWhitelist.split(",")));
			}
			if (exportGradleType != null) {
				args.setExportGradleType(
						jadx.core.export.ExportGradleType.valueOf(exportGradleType.toUpperCase()));
			}
			if (generatedRenamesMappingFile != null) {
				args.setGeneratedRenamesMappingFile(new java.io.File(generatedRenamesMappingFile));
			}
			if (disabledPasses != null) {
				args.getDisabledPasses().addAll(java.util.Arrays.asList(disabledPasses.split(",")));
			}
			if (pluginOptionsStr != null) {
				java.util.Map<String, String> pluginOpts = new java.util.LinkedHashMap<>();
				for (String pair : pluginOptionsStr.split(",")) {
					String[] kv = pair.split("=", 2);
					if (kv.length == 2) {
						pluginOpts.put(kv[0].trim(), kv[1].trim());
					}
				}
				args.setPluginOptions(pluginOpts);
			}
			if (disabledPluginsStr != null) {
				args.setDisabledPlugins(new java.util.HashSet<>(java.util.Arrays.asList(disabledPluginsStr.split(","))));
			}

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
