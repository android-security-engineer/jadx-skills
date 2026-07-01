# JADX Script API — Writing Java Programs Against JADX

This guide is for AI agents that want to write standalone Java programs that use JADX as a library for APK analysis, rather than using the CLI.

---

## 1. Project Setup

### Gradle (build.gradle.kts)
```kotlin
plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    // Core decompiler
    implementation("io.github.skylot:jadx-core:1.5.1")
    // Required transitive dependencies
    implementation("io.github.skylot:jadx-plugins:jadx-input-api:1.5.1")
    implementation("io.github.skylot:jadx-plugins:jadx-dex-input:1.5.1")
    implementation("io.github.skylot:jadx-plugins:jadx-java-input:1.5.1")
    implementation("io.github.skylot:jadx-plugins:jadx-smali-input:1.5.1")
    implementation("io.github.skylot:jadx-plugins:jadx-raft-input:1.5.1")
}

tasks.jar {
    manifest { attributes["Main-Class"] = "com.example.ApkAnalyzer" }
}
```

### Maven (pom.xml)
```xml
<dependencies>
    <dependency>
        <groupId>io.github.skylot</groupId>
        <artifactId>jadx-core</artifactId>
        <version>1.5.1</version>
    </dependency>
    <!-- Add input plugins as needed -->
</dependencies>
```

### Using Local Fork
```kotlin
dependencies {
    implementation(project(":jadx-core"))
    implementation(project(":jadx-plugins:jadx-dex-input"))
    implementation(project(":jadx-plugins:jadx-java-input"))
    implementation(project(":jadx-plugins:jadx-smali-input"))
    implementation(project(":jadx-plugins:jadx-raft-input"))
}
```

---

## 2. Common Program Patterns

### Pattern 1: Basic APK Analysis
```java
import jadx.api.*;
import java.io.File;
import java.util.List;

public class ApkAnalyzer {
    public static void main(String[] args) throws Exception {
        JadxArgs jadxArgs = new JadxArgs();
        jadxArgs.setInputFile(new File(args[0]));
        jadxArgs.setSkipResources(true);
        jadxArgs.setDeobfuscationOn(true);

        try (JadxDecompiler decompiler = new JadxDecompiler(jadxArgs)) {
            decompiler.load();

            System.out.println("Classes: " + decompiler.getClasses().size());
            System.out.println("Errors:  " + decompiler.getErrorsCount());

            for (JavaClass cls : decompiler.getClasses()) {
                System.out.println(cls.getFullName());
            }
        }
    }
}
```

### Pattern 2: Find All Activities
```java
public class ActivityFinder {
    public static void main(String[] args) throws Exception {
        JadxArgs jadxArgs = new JadxArgs();
        jadxArgs.setInputFile(new File(args[0]));
        try (JadxDecompiler decompiler = new JadxDecompiler(jadxArgs)) {
            decompiler.load();

            decompiler.getClasses().stream()
                .filter(cls -> cls.getFullName().endsWith("Activity")
                    || cls.getFullName().endsWith("Activity$"))
                .forEach(cls -> {
                    System.out.println("Activity: " + cls.getFullName());
                    // Check if it's in the manifest
                    try {
                        String code = cls.getCode();
                        if (code.contains("onCreate")) {
                            System.out.println("  Has onCreate()");
                        }
                    } catch (Exception e) {
                        System.out.println("  (decompilation error)");
                    }
                });
        }
    }
}
```

### Pattern 3: Build Complete Call Graph
```java
import java.util.*;
import jadx.api.*;

public class CallGraphBuilder {
    private final JadxDecompiler decompiler;
    private final Map<String, Set<String>> graph = new HashMap<>();

    public CallGraphBuilder(JadxDecompiler decompiler) {
        this.decompiler = decompiler;
    }

    public void buildFromEntry(String className, int maxDepth) {
        JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
        if (cls == null) return;
        traverse(cls.getFullName(), maxDepth, new HashSet<>());
    }

    private void traverse(String nodeName, int depth, Set<String> visited) {
        if (depth <= 0 || !visited.add(nodeName)) return;
        graph.putIfAbsent(nodeName, new HashSet<>());

        JavaClass cls = decompiler.searchJavaClassByOrigFullName(nodeName);
        if (cls == null) return;

        for (JavaMethod mth : cls.getMethods()) {
            try {
                for (JavaNode used : mth.getUsed()) {
                    String usedName = used.getFullName();
                    graph.get(nodeName).add(usedName);
                    if (used instanceof JavaClass) {
                        traverse(usedName, depth - 1, visited);
                    }
                }
            } catch (Exception ignored) {}
        }
    }

    public void printGraph() {
        for (var entry : graph.entrySet()) {
            for (String target : entry.getValue()) {
                System.out.println(entry.getKey() + " -> " + target);
            }
        }
    }
}
```

### Pattern 4: Extract All String Constants
```java
import java.util.*;
import jadx.api.*;
import jadx.api.metadata.*;
import jadx.api.metadata.annotations.*;
import jadx.core.dex.nodes.*;

public class StringExtractor {
    public static void main(String[] args) throws Exception {
        JadxArgs jadxArgs = new JadxArgs();
        jadxArgs.setInputFile(new File(args[0]));
        try (JadxDecompiler decompiler = new JadxDecompiler(jadxArgs)) {
            decompiler.load();

            for (JavaClass cls : decompiler.getClasses()) {
                try {
                    ICodeInfo codeInfo = cls.getCodeInfo();
                    ICodeMetadata metadata = codeInfo.getCodeMetadata();

                    // Search through code for string patterns
                    String code = codeInfo.getCodeStr();
                    for (String line : code.split("\n")) {
                        // Extract string literals
                        if (line.contains("\"http://") || line.contains("\"https://")) {
                            System.out.println(cls.getFullName() + ": " + line.trim());
                        }
                    }
                } catch (Exception ignored) {}
            }
        }
    }
}
```

### Pattern 5: Bulk Rename & Export
```java
import jadx.api.*;
import jadx.api.data.impl.*;
import java.io.File;

public class BulkRenamer {
    public static void main(String[] args) throws Exception {
        JadxArgs jadxArgs = new JadxArgs();
        jadxArgs.setInputFile(new File(args[0]));
        jadxArgs.setOutDir(new File("output"));
        jadxArgs.setDeobfuscationOn(true);

        try (JadxDecompiler decompiler = new JadxDecompiler(jadxArgs)) {
            decompiler.load();

            // Find obfuscated classes (single-letter names)
            for (JavaClass cls : decompiler.getClasses()) {
                String simpleName = cls.getName();
                if (simpleName.length() == 1) {
                    // Infer name from parent/interface
                    String parentName = cls.getTopParentClass().getName();
                    String newName = inferName(cls);
                    if (newName != null) {
                        System.out.println("Rename: " + cls.getFullName() + " -> " + newName);
                        cls.getClassNode().getClassInfo().setAlias(newName);
                    }
                }
            }

            // Apply renames
            decompiler.reloadCodeData();

            // Export
            decompiler.save();
        }
    }

    private static String inferName(JavaClass cls) {
        // Check if extends Activity
        try {
            String code = cls.getCode();
            if (code.contains("extends Activity") || code.contains("extends AppCompatActivity")) {
                return "ObfuscatedActivity";
            }
            if (code.contains("extends Fragment")) {
                return "ObfuscatedFragment";
            }
            if (code.contains("extends Service")) {
                return "ObfuscatedService";
            }
        } catch (Exception ignored) {}
        return null;
    }
}
```

### Pattern 6: Resource Analysis
```java
import jadx.api.*;
import java.io.File;

public class ResourceAnalyzer {
    public static void main(String[] args) throws Exception {
        JadxArgs jadxArgs = new JadxArgs();
        jadxArgs.setInputFile(new File(args[0]));
        // IMPORTANT: Don't skip resources
        jadxArgs.setSkipResources(false);

        try (JadxDecompiler decompiler = new JadxDecompiler(jadxArgs)) {
            decompiler.load();

            for (ResourceFile rf : decompiler.getResources()) {
                System.out.printf("[%s] %s%n", rf.getType(), rf.getDeobfName());

                if (rf.getType() == ResourceType.MANIFEST) {
                    try {
                        ResourceFileContent content = rf.loadContent();
                        System.out.println(content.getText());
                    } catch (Exception e) {
                        System.out.println("  (error loading manifest)");
                    }
                }
            }
        }
    }
}
```

### Pattern 7: Using the Script Command (JavaScript)
```java
// Write a .js file:
// var classes = decompiler.getClasses();
// for each (var cls in classes) {
//     if (cls.getFullName().contains("Activity")) {
//         print(cls.getFullName());
//     }
// }
// Then run: jadx-ai script find-activities.js app.apk
```

---

## 3. Important API Notes for AI Agents

### Accessing Internal APIs
Some useful features are in `@ApiStatus.Internal` classes. Use with caution:

```java
// Get internal ClassNode (for advanced operations)
ClassNode classNode = cls.getClassNode();

// Get internal MethodNode (for CFG, etc.)
MethodNode methodNode = method.getMethodNode();

// Get RootNode (for global operations)
RootNode root = decompiler.getRoot();
```

### Code Caching
By default, JADX uses `InMemoryCodeCache` which caches decompiled code. For long-running analysis:
- This is fine — it avoids re-decompiling the same class
- Call `cls.unload()` to free memory if you're done with a class
- Call `cls.reload()` to force re-decompilation (e.g., after renaming)

### Thread Safety
- `JadxDecompiler` is NOT thread-safe
- If parallelizing, use one `JadxDecompiler` per thread (each loads the APK independently)
- Or synchronize access to a single decompiler

### Error Handling
```java
try (JadxDecompiler decompiler = new JadxDecompiler(jadxArgs)) {
    decompiler.load();

    // Check for decompilation errors
    if (decompiler.getErrorsCount() > 0) {
        System.err.println("Decompilation had " + decompiler.getErrorsCount() + " errors");
        decompiler.printErrorsReport();
    }

    // Individual class errors
    for (JavaClass cls : decompiler.getClasses()) {
        try {
            String code = cls.getCode();
        } catch (Exception e) {
            System.err.println("Failed to decompile " + cls.getFullName() + ": " + e.getMessage());
        }
    }
}
```

### Memory Management for Large APKs
```java
JadxArgs args = new JadxArgs();
args.setInputFile(new File("large.apk"));
args.setSkipResources(true);  // Don't load resources

// Use class filter to limit processing
args.setClassFilter(name -> name.startsWith("com.target."));

try (JadxDecompiler decompiler = new JadxDecompiler(args)) {
    decompiler.load();

    // Process classes one at a time and unload
    for (JavaClass cls : decompiler.getClasses()) {
        String code = cls.getCode();
        // ... process code ...
        cls.unload();  // Free memory
    }
}
```
