package jadx.ai.cli.commands;

import java.util.HashMap;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.core.utils.DotGraphUtils;

@Command(name = "cfg", description = "Generate control flow graph for a method")
public class CfgCommand extends AbstractCommand {

    @Option(names = {"-c", "--class"}, description = "Class name", required = true)
    protected String className;

    @Option(names = {"-m", "--method"}, description = "Method name (required for CFG)")
    protected String methodName;

    @Option(names = {"--cfg-type"}, description = "CFG type: basic, raw, region", defaultValue = "basic")
    protected String cfgType;

    @Option(names = {"--format"}, description = "Output format: dot, text", defaultValue = "dot")
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

        boolean useRegions = "region".equals(cfgType);
        boolean rawInsn = "raw".equals(cfgType);
        DotGraphUtils utils = new DotGraphUtils(useRegions, rawInsn);
        String dotGraph = utils.dumpToString(method.getMethodNode());
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
