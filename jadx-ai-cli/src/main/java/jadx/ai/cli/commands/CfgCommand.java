package jadx.ai.cli.commands;

import java.util.HashMap;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.core.dex.nodes.MethodNode;
import jadx.core.utils.DotGraphUtils;
import jadx.core.utils.exceptions.DecodeException;

@Command(name = "cfg", description = "Generate control flow graph for a method")
public class CfgCommand extends AbstractCommand {

    @Option(names = {"-c", "--class"}, description = "Class name", required = true)
    protected String className;

    @Option(names = {"-m", "--method"}, description = "Method name (required for CFG)")
    protected String methodName;

    @Option(names = {"--cfg-type"}, description = "CFG type: basic, raw, region", defaultValue = "basic")
    protected String cfgType;

    @Option(names = {"--cfg-format"}, description = "CFG serialization: dot, text", defaultValue = "dot")
    protected String outputFormat;

    @Override
    protected Object execute(JadxDecompiler decompiler) throws Exception {
        JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
        if (cls == null) {
            return JsonOutput.error("ClassNotFound", "Class not found: " + className);
        }
        if (methodName == null) {
            return JsonOutput.error("MethodRequired", "Method name is required for CFG generation");
        }
        JavaMethod method = null;
        for (JavaMethod m : cls.getMethods()) {
            if (m.getName().equals(methodName)) {
                method = m;
                break;
            }
        }
        if (method == null) {
            return JsonOutput.error("MethodNotFound", "Method not found: " + methodName);
        }

        // The method node's basic blocks / instructions only exist after the decompilation
        // passes (BlockSplitter, region maker, ...) have run. A freshly-loaded decompiler has
        // not processed any method yet, so force the parent class through decompilation first —
        // otherwise dumpToString() sees null blocks AND null instructions and always fails.
        MethodNode mthNode = method.getMethodNode();
        ensureProcessed(mthNode);

        boolean useRegions = "region".equals(cfgType);
        boolean rawInsn = "raw".equals(cfgType);
        DotGraphUtils utils = new DotGraphUtils(useRegions, rawInsn);
        String dotGraph = utils.dumpToString(mthNode);
        if (dotGraph == null) {
            return JsonOutput.error("NoGraph", "Could not generate CFG (method may have no basic blocks)");
        }

        Map<String, Object> result = new HashMap<>();
        result.put("class", cls.getFullName());
        result.put("method", method.getName());
        result.put("cfgType", cfgType);
        result.put("format", outputFormat);
        result.put("graph", dotGraph);
        return JsonOutput.ok(result);
    }

    /**
     * Force the method through enough of the pipeline that its basic blocks (or at least raw
     * instructions) are populated. Decompiling the parent class runs the block-splitting and
     * region passes; if that still leaves no blocks (e.g. abstract/native), a bare load() at
     * least yields the instruction list for the single-block fallback in dumpToString().
     */
    private static void ensureProcessed(MethodNode mth) {
        try {
            if (mth.getBasicBlocks() == null) {
                mth.getParentClass().decompile();
            }
            if (mth.getBasicBlocks() == null && mth.getInstructions() == null) {
                mth.load();
            }
        } catch (DecodeException | RuntimeException e) {
            // best-effort: dumpToString() will report NoGraph if blocks are still absent
        }
    }

    @Override
    protected Map<String, Object> buildDaemonArgs() {
        Map<String, Object> args = new HashMap<>();
        args.put("class", className);
        args.put("method", methodName);
        args.put("cfgType", cfgType);
        args.put("format", outputFormat);
        return args;
    }
}
