package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaPackage;

@Command(name = "package-detail", description = "Get detailed package structure (sub-packages, classes, raw names)")
public class PackageDetailCommand extends AbstractCommand {

	@Option(names = { "-p", "--package" }, description = "Package name (full name)", required = true)
	protected String packageName;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		JavaPackage targetPkg = null;
		for (JavaPackage pkg : decompiler.getPackages()) {
			if (pkg.getFullName().equals(packageName)) {
				targetPkg = pkg;
				break;
			}
		}
		if (targetPkg == null) {
			List<String> suggestions = decompiler.getPackages()
					.stream()
					.map(JavaPackage::getFullName)
					.filter(n -> n.contains(packageName))
					.collect(Collectors.toList());
			return JsonOutput.error("PackageNotFound",
					"Package not found: " + packageName + ". Similar: " + suggestions);
		}

		PackageDetail detail = new PackageDetail();
		detail.name = targetPkg.getName();
		detail.fullName = targetPkg.getFullName();
		detail.rawName = targetPkg.getRawName();
		detail.rawFullName = targetPkg.getRawFullName();
		detail.isRoot = targetPkg.isRoot();
		detail.isLeaf = targetPkg.isLeaf();
		detail.isDefault = targetPkg.isDefault();

		detail.subPackages = new ArrayList<>();
		for (JavaPackage sub : targetPkg.getSubPackages()) {
			SubPackageInfo subInfo = new SubPackageInfo();
			subInfo.name = sub.getName();
			subInfo.fullName = sub.getFullName();
			subInfo.classCount = sub.getClasses().size();
			detail.subPackages.add(subInfo);
		}

		detail.classes = new ArrayList<>();
		for (JavaClass cls : targetPkg.getClasses()) {
			ClassInfo clsInfo = new ClassInfo();
			clsInfo.fullName = cls.getFullName();
			clsInfo.simpleName = cls.getName();
			clsInfo.isInner = cls.isInner();
			clsInfo.accessStr = cls.getAccessInfo().toString();
			detail.classes.add(clsInfo);
		}

		detail.classCount = targetPkg.getClasses().size();
		detail.classCountNoDup = targetPkg.getClassesNoDup().size();

		return JsonOutput.ok(detail);
	}

	static class PackageDetail {
		String name;
		String fullName;
		String rawName;
		String rawFullName;
		boolean isRoot;
		boolean isLeaf;
		boolean isDefault;
		List<SubPackageInfo> subPackages;
		List<ClassInfo> classes;
		int classCount;
		int classCountNoDup;
	}

	static class SubPackageInfo {
		String name;
		String fullName;
		int classCount;
	}

	static class ClassInfo {
		String fullName;
		String simpleName;
		boolean isInner;
		String accessStr;
	}
}
