package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaField;
import jadx.api.JavaMethod;

@Command(name = "class-detail", description = "Get detailed class structure (inheritance, inner classes, access flags, method signatures)")
public class ClassDetailCommand extends AbstractCommand {

	@Option(names = { "-c", "--class" }, description = "Full class name", required = true)
	protected String className;

	@Option(names = { "--method-short-id" }, description = "Search method by short ID (e.g. 'onCreate(Landroid/os/Bundle;)V')")
	protected String methodShortId;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		JavaClass cls = decompiler.searchJavaClassByOrigFullName(className);
		if (cls == null) {
			List<JavaClass> matches = decompiler.getClasses()
					.stream()
					.filter(c -> c.getFullName().contains(className))
					.collect(Collectors.toList());
			if (matches.isEmpty()) {
				return JsonOutput.error("ClassNotFound", "Class not found: " + className);
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

		ClassDetail detail = new ClassDetail();
		detail.fullName = cls.getFullName();
		detail.simpleName = cls.getName();
		detail.packageName = cls.getPackage();
		detail.rawName = cls.getRawName();
		detail.isInner = cls.isInner();
		detail.accessFlags = cls.getAccessInfo().rawValue();
		detail.accessStr = cls.getAccessInfo().toString();

		if (cls.getDeclaringClass() != null) {
			detail.declaringClass = cls.getDeclaringClass().getFullName();
		}
		detail.topParentClass = cls.getTopParentClass().getFullName();

		detail.innerClasses = new ArrayList<>();
		for (JavaClass inner : cls.getInnerClasses()) {
			detail.innerClasses.add(inner.getFullName());
		}

		detail.inlinedClasses = new ArrayList<>();
		for (JavaClass inlined : cls.getInlinedClasses()) {
			detail.inlinedClasses.add(inlined.getFullName());
		}

		detail.methods = new ArrayList<>();
		for (JavaMethod m : cls.getMethods()) {
			MethodDetail md = new MethodDetail();
			md.name = m.getName();
			md.returnType = m.getReturnType().toString();
			md.arguments = new ArrayList<>();
			for (jadx.core.dex.instructions.args.ArgType arg : m.getArguments()) {
				md.arguments.add(arg.toString());
			}
			md.isConstructor = m.isConstructor();
			md.isClassInit = m.isClassInit();
			md.accessFlags = m.getAccessFlags().rawValue();
			md.accessStr = m.getAccessFlags().toString();
			md.defPos = m.getDefPos();
			detail.methods.add(md);
		}

		detail.fields = new ArrayList<>();
		for (JavaField f : cls.getFields()) {
			FieldDetail fd = new FieldDetail();
			fd.name = f.getName();
			fd.rawName = f.getRawName();
			fd.type = f.getType().toString();
			fd.accessFlags = f.getAccessFlags().rawValue();
			fd.accessStr = f.getAccessFlags().toString();
			fd.defPos = f.getDefPos();
			detail.fields.add(fd);
		}

		detail.dependencies = new ArrayList<>();
		for (JavaClass dep : cls.getDependencies()) {
			detail.dependencies.add(dep.getFullName());
		}
		detail.totalDepsCount = cls.getDependencies().size();
		if (cls.getCodeParent() != null) {
			detail.codeParent = cls.getCodeParent().getFullName();
		}
		if (cls.getOriginalTopParentClass() != null) {
			detail.originalTopParentClass = cls.getOriginalTopParentClass().getFullName();
		}
		detail.isNoCode = cls.isNoCode();

		return JsonOutput.ok(detail);
	}

	static class ClassDetail {
		String fullName;
		String simpleName;
		String packageName;
		String rawName;
		boolean isInner;
		int accessFlags;
		String accessStr;
		String declaringClass;
		String topParentClass;
		List<String> innerClasses;
		List<String> inlinedClasses;
		List<MethodDetail> methods;
		List<FieldDetail> fields;
		List<String> dependencies;
		int totalDepsCount;
		String codeParent;
		String originalTopParentClass;
		boolean isNoCode;
		String javaPackage;
		String foundMethod;
	}

	static class MethodDetail {
		String name;
		String returnType;
		List<String> arguments;
		boolean isConstructor;
		boolean isClassInit;
		int accessFlags;
		String accessStr;
		int defPos;
	}

	static class FieldDetail {
		String name;
		String rawName;
		String type;
		int accessFlags;
		String accessStr;
		int defPos;
	}
}
