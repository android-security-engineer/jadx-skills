package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;

@Command(name = "decompile", description = "Decompile class(es) or method(s) to Java source")
public class DecompileCommand extends AbstractCommand {

	@Option(names = { "-c", "--class" }, description = "Full class name (e.g. com.example.MyClass)", required = true)
	protected String className;

	@Option(names = { "-m", "--method" }, description = "Method name (optional, decompile only this method)")
	protected String methodName;

	@Option(names = { "--with-smali" }, description = "Include smali/disassembly output")
	protected boolean withSmali;

	@Option(names = { "--line-map" }, description = "Include decompiled-to-source line mapping")
	protected boolean includeLineMap;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			List<JavaClass> matches = decompiler.getClasses()
					.stream()
					.filter(c -> c.getFullName().contains(className))
					.collect(Collectors.toList());
			if (matches.isEmpty()) {
				return JsonOutput.error("ClassNotFound",
						"No class found matching: " + className);
			}
			if (matches.size() > 1) {
				List<String> names = matches.stream()
						.map(JavaClass::getFullName)
						.collect(Collectors.toList());
				return JsonOutput.error("AmbiguousClass",
						"Multiple classes match. Specify full name: " + names);
			}
			cls = matches.get(0);
		}

		if (methodName != null && !methodName.isEmpty()) {
			return decompileMethod(cls, methodName);
		}
		return decompileClass(cls);
	}

	private Object decompileClass(JavaClass cls) {
		DecompileResult result = new DecompileResult();
		result.className = cls.getFullName();
		result.sourceCode = cls.getCode();
		if (includeLineMap) {
			result.sourceLineMap = cls.getCodeInfo().getCodeMetadata().getLineMapping();
		}
		if (withSmali) {
			result.smali = cls.getSmali();
		}
		return JsonOutput.ok(result);
	}

	private Object decompileMethod(JavaClass cls, String methodName) {
		List<JavaMethod> methods = cls.getMethods()
				.stream()
				.filter(m -> m.getName().equals(methodName))
				.collect(Collectors.toList());

		if (methods.isEmpty()) {
			return JsonOutput.error("MethodNotFound",
					"Method '" + methodName + "' not found in " + cls.getFullName());
		}

		List<MethodResult> methodResults = new ArrayList<>();
		for (JavaMethod m : methods) {
			MethodResult mr = new MethodResult();
			mr.methodName = m.getName();
			mr.returnType = m.getReturnType().toString();
			mr.sourceCode = m.getCodeStr();
			methodResults.add(mr);
		}

		DecompileResult result = new DecompileResult();
		result.className = cls.getFullName();
		result.methods = methodResults;
		if (methods.size() == 1) {
			result.sourceCode = methods.get(0).getCodeStr();
		}
		return JsonOutput.ok(result);
	}

	static class DecompileResult {
		String className;
		String sourceCode;
		String smali;
		List<MethodResult> methods;
		Map<Integer, Integer> sourceLineMap;
	}

	static class MethodResult {
		String methodName;
		String returnType;
		String sourceCode;
	}
}
