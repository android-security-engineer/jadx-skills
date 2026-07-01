# JadxDecompiler API Reference

`jadx.api.JadxDecompiler` is the main entry point for all JADX operations. It holds the decompilation state and provides access to all decompiled artifacts.

**Package**: `jadx.api`  
**JavaDoc**: See source at `jadx-core/src/main/java/jadx/api/JadxDecompiler.java`

---

## Lifecycle

```java
// 1. Create with configuration
JadxArgs args = new JadxArgs();
args.setInputFile(new File("app.apk"));
JadxDecompiler decompiler = new JadxDecompiler(args);

// 2. Load and decompile
decompiler.load();

// 3. Query results
List<JavaClass> classes = decompiler.getClasses();
List<ResourceFile> resources = decompiler.getResources();

// 4. Close when done (JadxDecompiler implements Closeable)
decompiler.close();

// Or use try-with-resources
try (JadxDecompiler decompiler = new JadxDecompiler(args)) {
    decompiler.load();
    // ... use decompiler ...
}
```

---

## Constructors

| Constructor | Description |
|-------------|-------------|
| `JadxDecompiler()` | Create with default JadxArgs |
| `JadxDecompiler(JadxArgs args)` | Create with custom configuration |

---

## Public Methods

### Loading & Lifecycle

| Method | Return | Description |
|--------|--------|-------------|
| `load()` | void | Load input files, run decompilation pipeline. **Must be called before any queries.** |
| `close()` | void | Release all resources, close input files, clean temp dirs. |
| `reloadPasses()` | void | Reload passes and plugins without re-processing classes. Useful after plugin changes. |
| `reloadCodeData()` | void | Notify code data listeners that data has changed (e.g., after renames). |

### Saving & Export

| Method | Return | Description |
|--------|--------|-------------|
| `save()` | void | Save all sources and resources to output directory. |
| `saveSources()` | void | Save only decompiled source code. |
| `saveResources()` | void | Save only decoded resources. |
| `save(int intervalInMillis, ProgressListener listener)` | void | Save with progress monitoring. Callback receives (done, total). |
| `getSaveTaskExecutor()` | ITaskExecutor | Get save task executor for custom scheduling. |

### Class Queries

| Method | Return | Description |
|--------|--------|-------------|
| `getClasses()` | `List<JavaClass>` | All top-level classes (excludes inner classes). |
| `getClassesWithInners()` | `List<JavaClass>` | All classes including inner classes. |
| `getPackages()` | `List<JavaPackage>` | All packages. |
| `searchJavaClassByOrigFullName(String fullName)` | `@Nullable JavaClass` | Find class by original full name (exact match). |
| `searchJavaClassByAliasFullName(String fullName)` | `@Nullable JavaClass` | Find class by alias/deobfuscated full name. |
| `searchJavaClassOrItsParentByOrigFullName(String fullName)` | `@Nullable JavaClass` | Find class, or its parent if it has DONT_GENERATE flag. |
| `searchClassNodeByOrigFullName(String fullName)` | `@Nullable ClassNode` | Find internal ClassNode by original name. **Internal API.** |

### Resource Queries

| Method | Return | Description |
|--------|--------|-------------|
| `getResources()` | `List<ResourceFile>` | All resources in the APK (manifest, XMLs, images, etc.). |

### Error Reporting

| Method | Return | Description |
|--------|--------|-------------|
| `getErrorsCount()` | int | Number of decompilation errors. |
| `getWarnsCount()` | int | Number of decompilation warnings. |
| `printErrorsReport()` | void | Print detailed error report to log. Includes missing classpath classes. |

### Node Resolution (Code Metadata)

| Method | Return | Description |
|--------|--------|-------------|
| `getJavaNodeByRef(ICodeNodeRef ref)` | `@Nullable JavaNode` | Convert an internal code reference to a public JavaNode. |
| `getJavaNodeByCodeAnnotation(ICodeInfo codeInfo, ICodeAnnotation ann)` | `@Nullable JavaNode` | Resolve any code annotation to a JavaNode. |
| `getJavaNodeAtPosition(ICodeInfo codeInfo, int pos)` | `@Nullable JavaNode` | Get JavaNode at exact character position in decompiled code. |
| `getClosestJavaNode(ICodeInfo codeInfo, int pos)` | `@Nullable JavaNode` | Get closest JavaNode above a character position. |
| `getEnclosingNode(ICodeInfo codeInfo, int pos)` | `@Nullable JavaNode` | Get enclosing class/method at a character position. |

### Plugin System

| Method | Return | Description |
|--------|--------|-------------|
| `registerPlugin(JadxPlugin plugin)` | void | Register a plugin before calling load(). |
| `addCustomCodeLoader(ICodeLoader loader)` | void | Add custom code input (e.g., from non-standard format). |
| `addCustomResourcesLoader(CustomResourcesLoader loader)` | void | Add custom resource loader. |
| `addCustomPass(JadxPass pass)` | void | Add custom decompilation pass. |
| `getCustomCodeLoaders()` | `List<ICodeLoader>` | Get registered custom code loaders. |
| `getCustomResourcesLoaders()` | `List<CustomResourcesLoader>` | Get registered custom resource loaders. |
| `getPluginManager()` | JadxPluginManager | Access the plugin manager. **Internal API.** |

### Internal APIs (Use with Caution)

| Method | Return | Description |
|--------|--------|-------------|
| `getRoot()` | RootNode | Get the internal RootNode. **@ApiStatus.Internal** |
| `convertClassNode(ClassNode cls)` | JavaClass | Convert internal ClassNode to public JavaClass. **@ApiStatus.Internal** |
| `convertFieldNode(FieldNode fld)` | JavaField | Convert internal FieldNode to public JavaField. **@ApiStatus.Internal** |
| `convertMethodNode(MethodNode mth)` | JavaMethod | Convert internal MethodNode to public JavaMethod. **@ApiStatus.Internal** |
| `convertPackageNode(PackageNode pkg)` | JavaPackage | Convert internal PackageNode to public JavaPackage. **@ApiStatus.Internal** |
| `convertNodes(Collection<ICodeNodeRef> nodes)` | `List<JavaNode>` | Batch convert internal refs. **@ApiStatus.Internal** |

### Accessors

| Method | Return | Description |
|--------|--------|-------------|
| `getArgs()` | JadxArgs | Get the configuration object. |
| `getResourcesLoader()` | ResourcesLoader | Get the resource loading engine. |
| `getZipReader()` | ZipReader | Get the ZIP reading engine. |
| `getDecompileScheduler()` | IDecompileScheduler | Get the decompile batch scheduler. |
| `events()` | IJadxEvents | Get the event bus. |
| `addCloseable(Closeable c)` | void | Register a resource to be closed with the decompiler. |

### Static Methods

| Method | Return | Description |
|--------|--------|-------------|
| `getVersion()` | String | Get JADX version string. |

---

## Node Conversion Flow

```
Internal (jadx.core.dex.nodes.*)    →    Public API (jadx.api.*)
─────────────────────────────────────────────────────────────
ClassNode                           →    JavaClass
MethodNode                          →    JavaMethod
FieldNode                           →    JavaField
PackageNode                         →    JavaPackage
```

The `convert*Node()` methods implement lazy caching — a JavaClass/JavaMethod/JavaField is created once and cached on the internal node. Subsequent calls return the cached instance.

---

## Thread Safety

- `JadxDecompiler` is **NOT thread-safe** for concurrent reads. If using from multiple threads, synchronize access.
- The daemon and MCP server both use synchronized dispatch for this reason.
- `getClasses()` is synchronized internally and caches results.
- Individual `JavaClass.getCode()` calls trigger decompilation which is also synchronized.

---

## Memory Considerations

- For large APKs (>10,000 classes), `getClasses()` returns all classes in memory.
- `getClassesWithInners()` includes inner classes — can be significantly larger.
- Use `classFilter` in JadxArgs to limit which classes are processed.
- Call `cls.unload()` to free a class's decompiled code from memory.
- The code cache (`ICodeCache`) stores decompiled code — `InMemoryCodeCache` (default) keeps everything in memory. Use `NoOpCodeCache` to disable.
- The usage info cache (`IUsageInfoCache`) stores cross-reference data — `InMemoryUsageInfoCache` (default) or `EmptyUsageInfoCache` to disable.

---

## Common Patterns

### Batch process all classes with progress
```java
List<JavaClass> classes = decompiler.getClasses();
int total = classes.size();
for (int i = 0; i < total; i++) {
    JavaClass cls = classes.get(i);
    String code = cls.getCode();
    // Process code...
    if (i % 100 == 0) {
        System.out.printf("Progress: %d/%d%n", i, total);
    }
}
```

### Search classes by pattern
```java
String pattern = "Activity";
List<JavaClass> matching = decompiler.getClasses().stream()
    .filter(cls -> cls.getFullName().contains(pattern))
    .collect(Collectors.toList());
```

### Trace deep usage chains
```java
void traceUsage(JavaNode node, int depth, Set<String> visited) {
    if (depth <= 0 || !visited.add(node.getFullName())) return;
    System.out.println("  ".repeat(3 - depth) + node.getFullName());
    if (node instanceof JavaClass) {
        for (JavaNode user : ((JavaClass) node).getUseIn()) {
            traceUsage(user, depth - 1, visited);
        }
    } else if (node instanceof JavaMethod) {
        for (JavaNode user : ((JavaMethod) node).getUseIn()) {
            traceUsage(user, depth - 1, visited);
        }
    }
}
```
