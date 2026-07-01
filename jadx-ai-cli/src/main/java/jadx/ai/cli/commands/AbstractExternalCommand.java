package jadx.ai.cli.commands;

import jadx.api.JadxDecompiler;

/**
 * Base class for commands that wrap an external tool (apktool, frida, adb, ...) rather than
 * driving the jadx decompiler. These commands do not load an APK: {@link #requiresDecompiler()}
 * returns false, so {@link #execute(JadxDecompiler)} is called with a {@code null} decompiler
 * which subclasses must ignore.
 *
 * <p>Subclasses declare their own picocli options (e.g. {@code --apk}, {@code --device}) and
 * typically delegate to {@link jadx.ai.cli.util.ExternalTool} for binary location, execution
 * with a timeout, and graceful "tool not installed" handling.
 */
public abstract class AbstractExternalCommand extends AbstractCommand {

	@Override
	protected boolean requiresDecompiler() {
		return false;
	}
}
