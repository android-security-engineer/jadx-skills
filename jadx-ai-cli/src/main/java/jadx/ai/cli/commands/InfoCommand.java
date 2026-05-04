package jadx.ai.cli.commands;

import picocli.CommandLine.Command;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;

@Command(name = "info", description = "Show APK/DEX file metadata and statistics")
public class InfoCommand extends AbstractCommand {

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		ApkInfo info = new ApkInfo();
		info.fileName = inputFile.getName();
		info.filePath = inputFile.getAbsolutePath();
		info.fileSize = inputFile.length();
		info.totalClasses = decompiler.getClasses().size();
		info.totalPackages = decompiler.getPackages().size();
		info.totalResources = decompiler.getResources().size();
		info.errorsCount = decompiler.getErrorsCount();
		info.warnsCount = decompiler.getWarnsCount();
		info.version = jadx.api.JadxDecompiler.getVersion();

		int methodCount = 0;
		int fieldCount = 0;
		for (jadx.api.JavaClass cls : decompiler.getClasses()) {
			methodCount += cls.getMethods().size();
			fieldCount += cls.getFields().size();
		}
		info.totalMethods = methodCount;
		info.totalFields = fieldCount;

		java.io.ByteArrayOutputStream errBaos = new java.io.ByteArrayOutputStream();
		java.io.PrintStream errPs = new java.io.PrintStream(errBaos);
		java.io.PrintStream oldErr = System.err;
		try {
			System.setErr(errPs);
			decompiler.printErrorsReport();
		} finally {
			System.setErr(oldErr);
		}
		info.errorsReport = errBaos.toString();

		return JsonOutput.ok(info);
	}

	static class ApkInfo {
		String fileName;
		String filePath;
		long fileSize;
		int totalClasses;
		int totalPackages;
		int totalMethods;
		int totalFields;
		int totalResources;
		int errorsCount;
		int warnsCount;
		String version;
		String errorsReport;
	}
}
