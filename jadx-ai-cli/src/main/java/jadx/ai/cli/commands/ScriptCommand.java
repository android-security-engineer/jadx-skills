package jadx.ai.cli.commands;

import java.io.File;
import java.nio.file.Files;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;

@Command(name = "script", description = "Run a script to operate on the decompiler instance")
public class ScriptCommand extends AbstractCommand {

	@Parameters(index = "1", description = "Script file path (.js)")
	protected File scriptFile;

	@Option(names = { "--engine" }, description = "Script engine: js (default)", defaultValue = "js")
	protected String engineName;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		if (!scriptFile.exists()) {
			return JsonOutput.error("ScriptNotFound",
					"Script file not found: " + scriptFile.getAbsolutePath());
		}

		String scriptContent = Files.readString(scriptFile.toPath());

		ScriptEngineManager manager = new ScriptEngineManager();
		ScriptEngine engine = manager.getEngineByName(engineName);
		if (engine == null) {
			return JsonOutput.error("EngineNotFound",
					"Script engine not found: " + engineName);
		}

		engine.put("decompiler", decompiler);
		engine.put("inputFile", inputFile);

		Object result = engine.eval(scriptContent);
		return JsonOutput.ok(result);
	}
}
