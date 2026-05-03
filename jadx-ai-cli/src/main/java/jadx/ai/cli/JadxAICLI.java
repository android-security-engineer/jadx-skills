package jadx.ai.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

import jadx.ai.cli.commands.ClassDetailCommand;
import jadx.ai.cli.commands.DecompileCommand;
import jadx.ai.cli.commands.ExportCommand;
import jadx.ai.cli.commands.InfoCommand;
import jadx.ai.cli.commands.LineMapCommand;
import jadx.ai.cli.commands.ListCommand;
import jadx.ai.cli.commands.PackageDetailCommand;
import jadx.ai.cli.commands.ResourcesCommand;
import jadx.ai.cli.commands.ScriptCommand;
import jadx.ai.cli.commands.SearchCommand;
import jadx.ai.cli.commands.UsageCommand;

@Command(
		name = "jadx-ai",
		description = "AI-friendly CLI for JADX decompiler - structured JSON output",
		subcommands = {
				ClassDetailCommand.class,
				DecompileCommand.class,
				SearchCommand.class,
				UsageCommand.class,
				ListCommand.class,
				ExportCommand.class,
				InfoCommand.class,
				ResourcesCommand.class,
				ScriptCommand.class,
				PackageDetailCommand.class,
				LineMapCommand.class
		},
		mixinStandardHelpOptions = true,
		version = "1.0.0"
)
public class JadxAICLI implements Runnable {
	@Override
	public void run() {
		CommandLine.usage(this, System.out);
	}

	public static void main(String[] args) {
		int exitCode = new CommandLine(new JadxAICLI()).execute(args);
		System.exit(exitCode);
	}
}
