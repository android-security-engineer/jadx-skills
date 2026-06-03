package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.List;
import java.util.Map;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;

@Command(name = "hook", description = "Generate Frida or Xposed hook snippets for reverse engineering")
public class HookCommand extends AbstractCommand {

	@Option(names = {"-t", "--type"}, description = "Hook type: frida, xposed", defaultValue = "frida")
	protected String hookType;

	@Option(names = {"-c", "--class"}, description = "Target class name (full name)")
	protected String className;

	@Option(names = {"-m", "--method"}, description = "Target method name (optional, hooks all methods if not specified)")
	protected String methodName;

	@Option(names = {"-f", "--field"}, description = "Target field name (optional)")
	protected String fieldName;

	@Option(names = {"--lang"}, description = "Xposed language: java, kotlin", defaultValue = "java")
	protected String xposedLang;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (className == null) {
			return JsonOutput.error("MissingClass", "--class is required");
		}
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			return JsonOutput.error("ClassNotFound", "Class not found: " + className);
		}

		switch (hookType) {
			case "frida":
				return generateFrida(cls);
			case "xposed":
				return generateXposed(cls);
			default:
				return JsonOutput.error("InvalidType", "Unknown hook type: " + hookType);
		}
	}

	private Object generateFrida(JavaClass cls) {
		StringBuilder sb = new StringBuilder();
		String rawName = cls.getRawName() != null ? cls.getRawName() : cls.getFullName();
		String shortName = cls.getName();

		// Class declaration
		sb.append("var ").append(shortName).append(" = Java.use(\"").append(rawName).append("\");\n");

		// Field hooks
		if (fieldName != null) {
			for (JavaField f : cls.getFields()) {
				if (f.getName().equals(fieldName) || f.getRawName().equals(fieldName)) {
					String rawFieldName = f.getRawName() != null ? f.getRawName() : f.getName();
					sb.append("\nvar ").append(f.getName()).append(" = ").append(shortName)
							.append(".").append(rawFieldName).append(".value;\n");
				}
			}
		}

		// Method hooks
		List<JavaMethod> targetMethods = new ArrayList<>();
		if (methodName != null) {
			for (JavaMethod m : cls.getMethods()) {
				if (m.getName().equals(methodName)) {
					targetMethods.add(m);
				}
			}
		} else if (fieldName == null) {
			targetMethods.addAll(cls.getMethods());
		}

		for (JavaMethod m : targetMethods) {
			String mthName = m.getName();
			String mthRawName = m.isConstructor() ? "$init" : mthName;
			boolean isOverloaded = isOverloaded(cls, mthName);

			// Build argument list
			String[] argInfo = buildFridaArgs(m);
			String argNames = argInfo[0];
			String logArgs = argInfo[1];
			String overloadSpec = "";
			if (isOverloaded) {
				overloadSpec = ".overload(" + buildOverloadArgs(m) + ")";
			}

			sb.append("\n");
			if (m.isConstructor() || isVoidReturn(m)) {
				sb.append(shortName).append("[\"").append(mthRawName).append("\"]")
						.append(overloadSpec).append(".implementation = function(").append(argNames).append(") {\n");
				sb.append("    console.log(`").append(shortName).append(".").append(mthName)
						.append(" is called").append(logArgs).append("`);\n");
				sb.append("    this[\"").append(mthRawName).append("\"](").append(argNames).append(");\n");
				sb.append("};\n");
			} else {
				sb.append(shortName).append("[\"").append(mthRawName).append("\"]")
						.append(overloadSpec).append(".implementation = function(").append(argNames).append(") {\n");
				sb.append("    console.log(`").append(shortName).append(".").append(mthName)
						.append(" is called").append(logArgs).append("`);\n");
				sb.append("    let result = this[\"").append(mthRawName).append("\"](").append(argNames).append(");\n");
				sb.append("    console.log(`").append(shortName).append(".").append(mthName)
						.append(" result=${result}`);\n");
				sb.append("    return result;\n");
				sb.append("};\n");
			}
		}

		Map<String, Object> result = new HashMap<>();
		result.put("type", "frida");
		result.put("class", cls.getFullName());
		result.put("snippet", sb.toString());
		return JsonOutput.ok(result);
	}

	private Object generateXposed(JavaClass cls) {
		StringBuilder sb = new StringBuilder();
		String rawName = cls.getRawName() != null ? cls.getRawName() : cls.getFullName();
		String shortName = cls.getName();
		boolean isKotlin = "kotlin".equals(xposedLang);

		// Class loader
		if (isKotlin) {
			sb.append("val ").append(shortName).append("Class = classLoader.loadClass(\"")
					.append(rawName).append("\")\n");
		} else {
			sb.append("Class<?> ").append(shortName).append("Class = classLoader.loadClass(\"")
					.append(rawName).append("\");\n");
		}

		// Method hooks
		List<JavaMethod> targetMethods = new ArrayList<>();
		if (methodName != null) {
			for (JavaMethod m : cls.getMethods()) {
				if (m.getName().equals(methodName)) {
					targetMethods.add(m);
				}
			}
		} else {
			targetMethods.addAll(cls.getMethods());
		}

		for (JavaMethod m : targetMethods) {
			String xposedMethod = m.isConstructor() ? "findAndHookConstructor" : "findAndHookMethod";
			StringBuilder argsBuilder = new StringBuilder();
			if (!m.isConstructor()) {
				argsBuilder.append("\"").append(m.getName()).append("\", ");
			}
			argsBuilder.append(shortName).append("Class, ");
			argsBuilder.append(buildXposedTypeArgs(m, isKotlin));

			sb.append("\n");
			if (isKotlin) {
				sb.append("XposedHelpers.").append(xposedMethod).append("(")
						.append(argsBuilder).append(", object : XC_MethodHook() {\n");
				sb.append("    override fun beforeHookedMethod(param: MethodHookParam) {\n");
				sb.append("        super.beforeHookedMethod(param)\n");
				sb.append("    }\n\n");
				sb.append("    override fun afterHookedMethod(param: MethodHookParam) {\n");
				sb.append("        super.afterHookedMethod(param)\n");
				sb.append("    }\n");
				sb.append("})\n");
			} else {
				sb.append("XposedHelpers.").append(xposedMethod).append("(")
						.append(argsBuilder).append(", new XC_MethodHook() {\n");
				sb.append("    @Override\n");
				sb.append("    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {\n");
				sb.append("        super.beforeHookedMethod(param);\n");
				sb.append("    }\n\n");
				sb.append("    @Override\n");
				sb.append("    protected void afterHookedMethod(MethodHookParam param) throws Throwable {\n");
				sb.append("        super.afterHookedMethod(param);\n");
				sb.append("    }\n");
				sb.append("});\n");
			}
		}

		// Field hooks
		if (fieldName != null) {
			for (JavaField f : cls.getFields()) {
				if (f.getName().equals(fieldName)) {
					String getter = buildXposedFieldGetter(f, isKotlin);
					sb.append("\n").append(getter).append("\n");
				}
			}
		}

		Map<String, Object> result = new HashMap<>();
		result.put("type", "xposed");
		result.put("language", xposedLang);
		result.put("class", cls.getFullName());
		result.put("snippet", sb.toString());
		return JsonOutput.ok(result);
	}

	private boolean isOverloaded(JavaClass cls, String methodName) {
		int count = 0;
		for (JavaMethod m : cls.getMethods()) {
			if (m.getName().equals(methodName)) {
				count++;
				if (count > 1) return true;
			}
		}
		return false;
	}

	private boolean isVoidReturn(JavaMethod m) {
		return m.getReturnType().toString().equals("void");
	}

	private String[] buildFridaArgs(JavaMethod m) {
		java.util.List<jadx.core.dex.instructions.args.ArgType> argTypes = m.getArguments();
		StringBuilder names = new StringBuilder();
		StringBuilder logParts = new StringBuilder();
		for (int i = 0; i < argTypes.size(); i++) {
			if (i > 0) {
				names.append(", ");
				logParts.append(", ");
			}
			String argName = "arg" + i;
			names.append(argName);
			logParts.append(argName).append("=${").append(argName).append("}");
		}
		String logArgs = logParts.length() > 0 ? ": " + logParts : "";
		return new String[]{names.toString(), logArgs};
	}

	private String buildOverloadArgs(JavaMethod m) {
		java.util.List<jadx.core.dex.instructions.args.ArgType> argTypes = m.getArguments();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < argTypes.size(); i++) {
			if (i > 0) sb.append(", ");
			String typeStr = argTypes.get(i).toString();
			if (typeStr.endsWith("[]")) {
				sb.append("'").append(typeStr.replace("/", ".")).append("'");
			} else {
				sb.append("'").append(typeStr).append("'");
			}
		}
		return sb.toString();
	}

	private String buildXposedTypeArgs(JavaMethod m, boolean isKotlin) {
		java.util.List<jadx.core.dex.instructions.args.ArgType> argTypes = m.getArguments();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < argTypes.size(); i++) {
			if (i > 0) sb.append(", ");
			String typeStr = argTypes.get(i).toString();
			sb.append(formatXposedType(typeStr, isKotlin));
		}
		return sb.toString();
	}

	private String formatXposedType(String type, boolean isKotlin) {
		switch (type) {
			case "boolean":
				return isKotlin ? "Boolean::class.javaPrimitiveType" : "boolean.class";
			case "char":
				return isKotlin ? "Char::class.javaPrimitiveType" : "char.class";
			case "byte":
				return isKotlin ? "Byte::class.javaPrimitiveType" : "byte.class";
			case "short":
				return isKotlin ? "Short::class.javaPrimitiveType" : "short.class";
			case "int":
				return isKotlin ? "Int::class.javaPrimitiveType" : "int.class";
			case "float":
				return isKotlin ? "Float::class.javaPrimitiveType" : "float.class";
			case "long":
				return isKotlin ? "Long::class.javaPrimitiveType" : "long.class";
			case "double":
				return isKotlin ? "Double::class.javaPrimitiveType" : "double.class";
			default:
				return "\"" + type + ".class\"";
		}
	}

	private String buildXposedFieldGetter(JavaField f, boolean isKotlin) {
		String rawFieldName = f.getRawName() != null ? f.getRawName() : f.getName();
		boolean isStatic = f.getAccessFlags().contains("static");
		String staticStr = isStatic ? "Static" : "";
		String typeStr = f.getType().toString();
		String typeSuffix = mapPrimitiveType(typeStr);
		String getter = "XposedHelpers.get" + staticStr + typeSuffix + "Field(";
		if (isKotlin) {
			getter += "/*runtimeObject*/, \"" + rawFieldName + "\")";
		} else {
			getter += "/*runtimeObject*/, \"" + rawFieldName + "\")";
		}
		return getter;
	}

	private String mapPrimitiveType(String type) {
		switch (type) {
			case "boolean": return "Boolean";
			case "char": return "Char";
			case "byte": return "Byte";
			case "short": return "Short";
			case "int": return "Int";
			case "float": return "Float";
			case "long": return "Long";
			case "double": return "Double";
			default: return "Object";
		}
	}

	@Override
	protected Map<String, Object> buildDaemonArgs() {
		Map<String, Object> args = new HashMap<>();
		args.put("type", hookType);
		args.put("class", className);
		if (methodName != null) args.put("method", methodName);
		if (fieldName != null) args.put("field", fieldName);
		args.put("lang", xposedLang);
		return args;
	}
}
