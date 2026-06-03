package jadx.ai.cli.commands;

import java.io.File;

import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import jadx.ai.cli.mcp.JadxMcpServer;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;

@Command(name = "mcp", description = "Start MCP server (JSON-RPC over stdio) for AI agent integration")
public class McpCommand implements Runnable {
	@Parameters(index = "0", description = "Input file (APK, DEX, JAR, AAR)")
	protected File inputFile;

	@Override
	public void run() {
		try {
			JadxArgs args = new JadxArgs();
			args.setInputFile(inputFile);
			args.setSkipResources(false);
			JadxDecompiler decompiler = new JadxDecompiler(args);
			decompiler.load();
			JadxMcpServer server = new JadxMcpServer(decompiler);
			server.run();
		} catch (Exception e) {
			System.err.println("MCP server error: " + e.getMessage());
		}
	}
}
