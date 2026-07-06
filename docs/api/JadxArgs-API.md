# JadxArgs API Reference — Full Configuration

`jadx.api.JadxArgs` holds all decompilation configuration options. Pass it to `JadxDecompiler(JadxArgs)` before calling `load()`.

**Package**: `jadx.api`  
**Implements**: `Closeable`

---

## Input & Output Configuration

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `inputFiles` | `List<File>` | empty | `setInputFile(File)` / `addInputFile(File)` | Input APK/DEX/JAR/AAR/class files |
| `outDir` | File | null | `setOutDir(File)` | Root output directory |
| `outDirSrc` | File | null | `setOutDirSrc(File)` | Source output subdirectory |
| `outDirRes` | File | null | `setOutDirRes(File)` | Resource output subdirectory |
| — | — | — | `setRootDir(File)` | Convenience: sets outDir + outDirSrc + outDirRes |

**Quick setup:**
```java
JadxArgs args = new JadxArgs();
args.setInputFile(new File("app.apk"));
args.setOutDir(new File("output"));
// Equivalent to:
// args.outDir = "output"
// args.outDirSrc = "output/sources"
// args.outDirRes = "output/resources"
```

---

## Decompilation Options

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `decompilationMode` | DecompilationMode | AUTO | `setDecompilationMode(...)` | AUTO, RESTRUCTURE, SIMPLE, FALLBACK |
| `showInconsistentCode` | boolean | false | `setShowInconsistentCode(...)` | Show bad/inconsistent code instead of error |
| `useImports` | boolean | true | `setUseImports(...)` | Generate import statements |
| `debugInfo` | boolean | true | `setDebugInfo(...)` | Include debug info in output |
| `insertDebugLines` | boolean | false | `setInsertDebugLines(...)` | Insert debug line numbers |
| `extractFinally` | boolean | true | `setExtractFinally(...)` | Extract finally blocks |
| `inlineAnonymousClasses` | boolean | true | `setInlineAnonymousClasses(...)` | Inline anonymous classes |
| `inlineMethods` | boolean | true | `setInlineMethods(...)` | Inline methods |
| `allowInlineKotlinLambda` | boolean | true | `setAllowInlineKotlinLambda(...)` | Allow inline Kotlin lambda |
| `moveInnerClasses` | boolean | true | `setMoveInnerClasses(...)` | Move inner classes |
| `escapeUnicode` | boolean | false | `setEscapeUnicode(...)` | Escape unicode characters |
| `replaceConsts` | boolean | true | `setReplaceConsts(...)` | Replace constants in code |
| `restoreSwitchOverString` | boolean | true | `setRestoreSwitchOverString(...)` | Restore switch-over-string patterns |
| `respectBytecodeAccModifiers` | boolean | false | `setRespectBytecodeAccModifiers(...)` | Respect bytecode access modifiers |
| `integerFormat` | IntegerFormat | AUTO | `setIntegerFormat(...)` | AUTO, DEC, HEX, OCT |
| `commentsLevel` | CommentsLevel | INFO | `setCommentsLevel(...)` | NONE, USER_ONLY, ERROR, WARN, INFO, DEBUG |

---

## Deobfuscation Options

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `deobfuscationOn` | boolean | false | `setDeobfuscationOn(...)` | Enable deobfuscation |
| `deobfuscationMinLength` | int | 0 | `setDeobfuscationMinLength(...)` | Min name length for rename |
| `deobfuscationMaxLength` | int | MAX_VALUE | `setDeobfuscationMaxLength(...)` | Max name length for rename |
| `deobfuscationWhitelist` | `List<String>` | default list | `setDeobfuscationWhitelist(...)` | Exclude classes/packages from deobf (suffix `.*`) |
| `useSourceNameAsClassNameAlias` | UseSourceNameAsClassNameAlias | default | `setUseSourceNameAsClassNameAlias(...)` | NO, YES, IF_NECESSARY |
| `sourceNameRepeatLimit` | int | 10 | `setSourceNameRepeatLimit(...)` | Limit repeated source name usage |
| `resourceNameSource` | ResourceNameSource | AUTO | `setResourceNameSource(...)` | AUTO, ORIG, DEOBF |
| `aliasProvider` | IAliasProvider | DeobfAliasProvider | `setAliasProvider(...)` | Custom alias provider |
| `renameCondition` | IRenameCondition | default | `setRenameCondition(...)` | Custom rename condition |

---

## Rename Configuration

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `renameFlags` | `Set<RenameEnum>` | all | `setRenameFlags(...)` | CASE, VALID, PRINTABLE |
| `fsCaseSensitive` | boolean | false | `setFsCaseSensitive(...)` | Filesystem case sensitivity |

**Convenience setters:**
```java
args.setRenameCaseSensitive(true);   // Rename to avoid case conflicts
args.setRenameValid(true);           // Rename to valid Java identifiers
args.setRenamePrintable(true);       // Rename to printable names
```

---

## Class Filtering

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `classFilter` | `Predicate<String>` | null | `setClassFilter(...)` | Filter which classes to process |
| `includeDependencies` | boolean | false | `setIncludeDependencies(...)` | Include dependencies of filtered classes |

```java
// Only decompile classes in com.example.app
args.setClassFilter(name -> name.startsWith("com.example.app."));
args.setIncludeDependencies(true);  // Also include their dependencies
```

---

## Mapping & Rename Persistence

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `userRenamesMappingsPath` | Path | null | `setUserRenamesMappingsPath(...)` | Path to mapping file |
| `userRenamesMappingsMode` | UserRenamesMappingsMode | IGNORE | `setUserRenamesMappingsMode(...)` | IGNORE, READ, READ_AND_APPLY, READ_APPLY_AND_SAVE |
| `generatedRenamesMappingFile` | File | null | `setGeneratedRenamesMappingFile(...)` | Output file for generated renames |
| `generatedRenamesMappingFileMode` | GeneratedRenamesMappingFileMode | default | `setGeneratedRenamesMappingFileMode(...)` | APPEND, OVERWRITE |

---

## Output Configuration

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `outputFormat` | OutputFormatEnum | JAVA | `setOutputFormat(...)` | JAVA, JSON |
| `codeNewLineStr` | String | system NL | `setCodeNewLineStr(...)` | Newline string |
| `codeIndentStr` | String | "    " | `setCodeIndentStr(...)` | Indent string (4 spaces) |
| `skipResources` | boolean | false | `setSkipResources(...)` | Skip resource decoding |
| `skipSources` | boolean | false | `setSkipSources(...)` | Skip source decompilation |
| `skipXmlPrettyPrint` | boolean | false | `setSkipXmlPrettyPrint(...)` | Skip XML pretty printing |
| `exportGradleType` | ExportGradleType | null | `setExportGradleType(...)` | AUTO, ANDROID_APP, ANDROID_LIBRARY, SIMPLE_JAVA |
| `exportAsGradleProject` | boolean | false | `setExportAsGradleProject(...)` | Enable Gradle export |

---

## Performance & Threading

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `threadsCount` | int | CPU/2 | `setThreadsCount(...)` | Processing thread count (min: 1) |
| `codeCache` | ICodeCache | InMemory | `setCodeCache(...)` | Code cache implementation |
| `usageInfoCache` | IUsageInfoCache | InMemory | `setUsageInfoCache(...)` | Usage info cache |
| `skipFilesSave` | boolean | false | `setSkipFilesSave(...)` | Don't write files (perf testing) |

---

## Plugin System

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `pluginLoader` | JadxPluginLoader | JadxBasePluginLoader | `setPluginLoader(...)` | Plugin discovery/loader |
| `pluginOptions` | `Map<String,String>` | empty | `setPluginOptions(...)` | Key=value plugin configuration |
| `disabledPlugins` | `Set<String>` | empty | `setDisabledPlugins(...)` | Plugin IDs to disable |
| `disabledPasses` | `List<String>` | empty | (getter only) | Pass names to disable |
| `useDxInput` | boolean | false | `setUseDxInput(...)` | Use DX input instead of java-input |
| `codeData` | ICodeData | null | `setCodeData(...)` | Custom code data (comments, renames) |

---

## Security

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `security` | IJadxSecurity | all flags | `setSecurity(...)` | Security validation configuration |

**Security flags** (JadxSecurityFlag enum):
- `VERIFY_APP_PACKAGE` — Verify APK package structure
- `SECURE_XML_PARSER` — Use secure XML parsing (prevent XXE)
- `SECURE_ZIP_READER` — Use secure ZIP reading (prevent zip slip)

```java
// Disable all security checks (NOT recommended for untrusted input)
args.setSecurity(new JadxSecurity(EnumSet.noneOf(JadxSecurityFlag.class)));

// Enable specific checks
args.setSecurity(new JadxSecurity(EnumSet.of(
    JadxSecurityFlag.SECURE_XML_PARSER,
    JadxSecurityFlag.SECURE_ZIP_READER)));
```

---

## Debug & Internal

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `cfgOutput` | boolean | false | `setCfgOutput(...)` | Enable CFG output |
| `rawCFGOutput` | boolean | false | `setRawCFGOutput(...)` | Enable raw CFG output |
| `runDebugChecks` | boolean | false | `setRunDebugChecks(...)` | Run expensive invariant checks |
| `typeUpdatesLimitCount` | int | 10 | `setTypeUpdatesLimitCount(...)` | Max type updates per instruction |
| `loadJadxClsSetFile` | boolean | true | `setLoadJadxClsSetFile(...)` | Load .jadxClsSet file |
| `useHeadersForDetectResourceExtensions` | boolean | false | `setUseHeadersForDetectResourceExtensions(...)` | Use file headers for resource type detection |
| `filesGetter` | IJadxFilesGetter | TempFilesGetter | `setFilesGetter(...)` | Temp/file directory provider |

---

## Kotlin-Specific Options

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `useKotlinMethodsForVarNames` | UseKotlinMethodsForVarNames | APPLY | `setUseKotlinMethodsForVarNames(...)` | DISABLE, APPLY, APPLY_AND_HIDE |

---

## Code Writer Provider

| Property | Type | Default | Setter | Description |
|----------|------|---------|--------|-------------|
| `codeWriterProvider` | `Function<JadxArgs, ICodeWriter>` | AnnotatedCodeWriter | `setCodeWriterProvider(...)` | Custom code writer factory |

---

## Complete Example — AI Agent Configuration

```java
JadxArgs args = new JadxArgs();
args.setInputFile(new File("target.apk"));
args.setOutDir(new File("analysis-output"));

// Decompilation tuning
args.setDecompilationMode(DecompilationMode.AUTO);
args.setShowInconsistentCode(true);  // Show bad code rather than skip
args.setCommentsLevel(CommentsLevel.WARN);

// Deobfuscation
args.setDeobfuscationOn(true);
args.setDeobfuscationMinLength(3);
args.setDeobfuscationMaxLength(64);

// Performance
args.setThreadsCount(8);

// Security — be strict with untrusted APKs
args.setSecurity(new JadxSecurity(JadxSecurityFlag.all()));

// Only process target package
args.setClassFilter(name -> name.startsWith("com.target."));
args.setIncludeDependencies(true);

try (JadxDecompiler decompiler = new JadxDecompiler(args)) {
    decompiler.load();
    // ... analysis ...
}
```
