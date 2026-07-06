# JADX API Quick Start for AI Agents

This guide helps AI agents quickly start using JADX as a Java library for programmatic APK/DEX analysis.

## 1. Add JADX as a Dependency

### Gradle (Kotlin DSL)
```kotlin
dependencies {
    implementation("io.github.skylot:jadx-core:1.5.1")  // Check latest version
}
```

### Maven
```xml
<dependency>
    <groupId>io.github.skylot</groupId>
    <artifactId>jadx-core</artifactId>
    <version>1.5.1</version>
</dependency>
```

### Alternative: Use Local JAR
If working with a custom fork, build the JAR first:
```bash
./gradlew :jadx-core:jar
# Then add the output JAR to your project's dependencies
```

## 2. Minimal Example — Decompile an APK

```java
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import java.io.File;

public class QuickStart {
    public static void main(String[] args) throws Exception {
        // Configure
        JadxArgs jadxArgs = new JadxArgs();
        jadxArgs.setInputFile(new File("target.apk"));
        jadxArgs.setSkipResources(true);  // Only decompile code, skip resources

        // Decompile
        try (JadxDecompiler decompiler = new JadxDecompiler(jadxArgs)) {
            decompiler.load();

            // Get all classes
            for (JavaClass cls : decompiler.getClasses()) {
                System.out.println("Class: " + cls.getFullName());
                System.out.println(cls.getCode());
            }

            // Search for a specific class
            JavaClass mainActivity = decompiler.searchJavaClassByOrigFullName(
                "com.example.app.MainActivity");
            if (mainActivity != null) {
                System.out.println("Found MainActivity!");
                System.out.println(mainActivity.getCode());
            }
        }
    }
}
```

## 3. Core API Lifecycle

```
JadxArgs → JadxDecompiler → load() → query classes/resources → close()
```

**Critical**: Always call `decompiler.load()` before querying. Always call `decompiler.close()` when done (JadxDecompiler implements Closeable).

## 4. Key API Patterns

### Access a specific class
```java
// By original full name (exact match)
JavaClass cls = decompiler.searchJavaClassByOrigFullName("com.example.MyClass");

// By alias/deobfuscated name
JavaClass cls = decompiler.searchJavaClassByAliasFullName("com.example.MyClass");

// If class has DONT_GENERATE flag, get its parent instead
JavaClass cls = decompiler.searchJavaClassOrItsParentByOrigFullName("com.example.a");
```

### Inspect a class
```java
JavaClass cls = decompiler.searchJavaClassByOrigFullName("com.example.MyClass");
cls.getName();              // Short name: "MyClass"
cls.getFullName();          // Full name: "com.example.MyClass"
cls.getRawName();           // Raw/obfuscated name
cls.getPackage();           // Package: "com.example.app"
cls.isInner();              // Is inner class?
cls.isNoCode();             // Has DONT_GENERATE flag?
cls.getAccessInfo();        // Access modifiers (public, final, etc.)

// Methods and fields
for (JavaMethod m : cls.getMethods()) {
    m.getName();            // Method name (alias)
    m.getFullName();        // Full signature
    m.getReturnType();      // Return type (ArgType)
    m.getArguments();       // Parameter types (List<ArgType>)
    m.isConstructor();      // Is constructor?
    m.getAccessFlags();     // Access modifiers
}

for (JavaField f : cls.getFields()) {
    f.getName();            // Field name (alias)
    f.getType();            // Field type
    f.getAccessFlags();     // Access modifiers
}

// Inner/inlined classes
cls.getInnerClasses();      // List of inner classes
cls.getInlinedClasses();    // List of inlined anonymous classes

// Dependencies
cls.getDependencies();      // Classes this class depends on
cls.getTotalDepsCount();    // Total dependency count
```

### Get source code
```java
// Full class source
String sourceCode = cls.getCode();

// With metadata (annotations, line mapping)
ICodeInfo codeInfo = cls.getCodeInfo();
String code = codeInfo.getCodeStr();
ICodeMetadata metadata = codeInfo.getCodeMetadata();

// Smali/disassembly
String smali = cls.getSmali();

// Specific method source
for (JavaMethod m : cls.getMethods()) {
    String methodCode = m.getCodeStr();  // Method-only source
}
```

### Find usage (cross-references)
```java
// Who uses this class/method/field?
List<JavaNode> users = cls.getUseIn();     // Classes that reference this class
List<JavaNode> users = method.getUseIn();  // Methods that call this method
List<JavaNode> users = field.getUseIn();   // Methods that access this field

// What does this method use?
List<JavaNode> used = method.getUsed();    // What this method calls/references

// Override-related methods (polymorphism)
List<JavaMethod> overrides = method.getOverrideRelatedMethods();

// Self-recursion check
boolean recursive = method.callsSelf();

// Unresolved references (calls to external/non-resolved methods)
List<IMethodRef> unresolved = method.getUnresolvedUsed();
```

### Code metadata & position resolution
```java
ICodeInfo codeInfo = cls.getCodeInfo();
ICodeMetadata metadata = codeInfo.getCodeMetadata();

// Line mapping: decompiled line → source line
Map<Integer, Integer> lineMap = metadata.getLineMapping();

// Find annotation at a character position
ICodeAnnotation ann = metadata.getAt(position);

// Find closest annotation above position
ICodeAnnotation ann = metadata.getClosestUp(position);

// Find enclosing node at position
ICodeNodeRef node = metadata.getNodeAt(position);

// Search for annotations from position downward
metadata.searchDown(startPos, (pos, annotation) -> {
    // Process each annotation
    return null;  // Continue search
});
```

### Rename identifiers (deobfuscation)
```java
// Rename a class
JavaClass cls = decompiler.searchJavaClassByOrigFullName("com.example.a");
cls.getClassNode().getAlias();  // Current alias
// Set new alias via internal API:
cls.getClassNode().getClassInfo().setAlias("MainActivity");

// Rename a method
JavaMethod method = cls.getMethods().get(0);
method.getMethodNode().getMethodInfo().setAlias("onCreate");

// Remove alias (revert to original)
cls.removeAlias();
method.removeAlias();

// After renaming, reload code data
decompiler.reloadCodeData();
```

### Reload/unload code
```java
// Reload (re-decompile) a class after changes
ICodeInfo newCode = cls.reload();

// Unload (free memory) a class's code
cls.unload();

// Refresh all code data (after bulk renames)
decompiler.reloadCodeData();

// Reload passes/plugins without re-loading APK
decompiler.reloadPasses();
```

### Resources
```java
// List all resources
List<ResourceFile> resources = decompiler.getResources();
for (ResourceFile rf : resources) {
    rf.getName();          // Resource name
    rf.getDeobfName();     // Deobfuscated name
    rf.getType();          // ResourceType enum: MANIFEST, XML, ARSC, IMG, etc.
    rf.getOriginalName();  // Original file name in APK
}

// Load resource content
ResourceFileContent content = rf.loadContent();
String text = content.getText();  // For text-based resources

// Or use ResourcesLoader directly for binary resources
ResContainer container = ResourcesLoader.loadContent(decompiler, rf);
```

### Save/export
```java
// Save all decompiled sources + resources to output directory
jadxArgs.setOutDir(new File("output"));
decompiler.save();

// Save only sources
decompiler.saveSources();

// Save only resources
decompiler.saveResources();

// Save with progress tracking
decompiler.save(1000, (done, total) -> {
    System.out.printf("Progress: %d/%d%n", done, total);
});
```

## 5. Configuration Reference (Key Options)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `inputFiles` | List<File> | empty | Input APK/DEX/JAR/AAR files |
| `outDir` | File | null | Output directory |
| `decompilationMode` | DecompilationMode | AUTO | AUTO, RESTRUCTURE, SIMPLE, FALLBACK |
| `skipResources` | boolean | false | Skip resource decoding |
| `skipSources` | boolean | false | Skip source decompilation |
| `showInconsistentCode` | boolean | false | Show bad/inconsistent code |
| `deobfuscationOn` | boolean | false | Enable deobfuscation |
| `deobfuscationMinLength` | int | 0 | Min name length for deobf renaming |
| `deobfuscationMaxLength` | int | MAX | Max name length for deobf renaming |
| `useImports` | boolean | true | Use import statements |
| `debugInfo` | boolean | true | Include debug info |
| `inlineAnonymousClasses` | boolean | true | Inline anonymous classes |
| `inlineMethods` | boolean | true | Inline methods |
| `moveInnerClasses` | boolean | true | Move inner classes |
| `extractFinally` | boolean | true | Extract finally blocks |
| `threadsCount` | int | CPU/2 | Processing thread count |
| `classFilter` | Predicate<String> | null | Filter classes by name pattern |
| `includeDependencies` | boolean | false | Include deps for filtered classes |
| `commentsLevel` | CommentsLevel | INFO | NONE, USER_ONLY, ERROR, WARN, INFO, DEBUG |
| `integerFormat` | IntegerFormat | AUTO | AUTO, DEC, HEX, OCT |
| `escapeUnicode` | boolean | false | Escape unicode chars |
| `replaceConsts` | boolean | true | Replace constants |
| `exportGradleType` | ExportGradleType | null | AUTO, ANDROID_APP, ANDROID_LIBRARY, SIMPLE_JAVA |
| `security` | IJadxSecurity | all flags | Security validation flags |

## 6. Error Handling

```java
// Check decompilation errors/warnings
int errors = decompiler.getErrorsCount();
int warns = decompiler.getWarnsCount();

// Print full error report
decompiler.printErrorsReport();

// Check if a class failed to decompile
if (cls.isNoCode()) {
    System.out.println("Class marked as DONT_GENERATE");
}
```

## 7. Common AI Agent Patterns

### Pattern: Find all network endpoints
```java
for (JavaClass cls : decompiler.getClasses()) {
    ICodeInfo code = cls.getCodeInfo();
    // Search code for HTTP patterns
    String source = code.getCodeStr();
    if (source.contains("http://") || source.contains("https://")) {
        System.out.println(cls.getFullName() + " contains network URLs");
    }
}
```

### Pattern: Find all encryption usage
```java
for (JavaClass cls : decompiler.getClasses()) {
    for (JavaMethod mth : cls.getMethods()) {
        String name = mth.getName().toLowerCase();
        if (name.contains("encrypt") || name.contains("decrypt")
            || name.contains("cipher") || name.contains("hash")) {
            System.out.println(mth.getFullName());
            // Trace who calls this crypto method
            for (JavaNode user : mth.getUseIn()) {
                System.out.println("  Called by: " + user.getFullName());
            }
        }
    }
}
```

### Pattern: Build call graph from entry point
```java
JavaClass entry = decompiler.searchJavaClassByOrigFullName("com.example.app.MainActivity");
for (JavaMethod mth : entry.getMethods()) {
    if (mth.getName().equals("onCreate")) {
        System.out.println("onCreate calls:");
        for (JavaNode used : mth.getUsed()) {
            System.out.println("  → " + used.getFullName());
        }
    }
}
```

### Pattern: Rename obfuscated identifiers
```java
// Enable deobfuscation in config
jadxArgs.setDeobfuscationOn(true);

// Or manually rename after loading
for (JavaClass cls : decompiler.getClasses()) {
    if (cls.getRawName().matches("com\\.example\\.a[0-9]+")) {
        // This looks like an obfuscated name
        cls.getClassNode().getClassInfo().setAlias("ObfuscatedClass_" + cls.getFullName());
    }
}
decompiler.reloadCodeData();  // Apply renames
```
