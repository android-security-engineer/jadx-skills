package jadx.ai.cli.commands;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;

@Command(name = "export", description = "Export decompiled classes to files")
public class ExportCommand extends AbstractCommand {

	@Option(names = { "-o", "--output" }, description = "Output directory", required = true)
	protected File outputDir;

	@Option(names = { "-p", "--package" }, description = "Export only classes in this package")
	protected String packageFilter;

	@Option(names = { "-c", "--class" }, description = "Export only this class (full name)")
	protected String classFilter;

	@Option(names = { "--export-format" }, description = "Export format: java (default) or smali", defaultValue = "java")
	protected String exportFormat;

	@Option(names = { "--save-all" }, description = "Use JADX save() to export all sources and resources to output dir")
	protected boolean saveAll;

	@Option(names = { "--save-sources" }, description = "Use JADX saveSources() to export only sources to output dir")
	protected boolean saveSources;

	@Option(names = { "--save-resources" }, description = "Use JADX saveResources() to export only resources to output dir")
	protected boolean saveResources;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (!outputDir.exists() && !outputDir.mkdirs()) {
			return JsonOutput.error("OutputError",
					"Cannot create output directory: " + outputDir);
		}

		if (saveAll) {
			decompiler.getArgs().setOutDir(outputDir);
			decompiler.getArgs().setOutDirSrc(new File(outputDir, "sources"));
			decompiler.getArgs().setOutDirRes(new File(outputDir, "resources"));
			decompiler.save();
			ExportSummary summary = new ExportSummary();
			summary.exportedCount = decompiler.getClasses().size();
			summary.errorCount = 0;
			summary.outputDir = outputDir.getAbsolutePath();
			return JsonOutput.ok(summary);
		}

		List<ExportResult> exported = new ArrayList<>();
		int errors = 0;

		for (JavaClass cls : decompiler.getClasses()) {
			if (packageFilter != null && !cls.getPackage().startsWith(packageFilter)) {
				continue;
			}
			if (classFilter != null && !cls.getFullName().equals(classFilter)) {
				continue;
			}

			try {
				String ext = "smali".equals(exportFormat) ? ".smali" : ".java";
				Path outputPath = outputDir.toPath()
						.resolve(cls.getFullName().replace('.', '/') + ext);
				Files.createDirectories(outputPath.getParent());

				String content = "smali".equals(exportFormat) ? cls.getSmali() : cls.getCode();
				Files.writeString(outputPath, content != null ? content : "");

				ExportResult r = new ExportResult();
				r.className = cls.getFullName();
				r.outputPath = outputPath.toString();
				exported.add(r);
			} catch (IOException e) {
				errors++;
			}
		}

		ExportSummary summary = new ExportSummary();
		summary.exportedCount = exported.size();
		summary.errorCount = errors;
		summary.outputDir = outputDir.getAbsolutePath();
		summary.files = exported;
		return JsonOutput.ok(summary);
	}

	static class ExportResult {
		String className;
		String outputPath;
	}

	static class ExportSummary {
		int exportedCount;
		int errorCount;
		String outputDir;
		List<ExportResult> files;
	}
}
