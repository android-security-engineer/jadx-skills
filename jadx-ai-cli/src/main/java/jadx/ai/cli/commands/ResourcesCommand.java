package jadx.ai.cli.commands;

import java.util.ArrayList;
import java.util.List;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import jadx.ai.cli.output.JsonOutput;
import jadx.api.JadxDecompiler;
import jadx.api.ResourceFile;
import jadx.api.ResourceType;

@Command(name = "resources", description = "List and read embedded resource files (AndroidManifest, XML, ARSC, etc.)")
public class ResourcesCommand extends AbstractCommand {

	@Option(
			names = { "-t", "--type" },
			description = "Filter by resource type: MANIFEST, XML, ARSC, IMG, FONT, JSON, TEXT, HTML, LIB, CODE, APK, ARCHIVE, VIDEOS, SOUNDS"
	)
	protected String resourceType;

	@Option(names = { "-n", "--name" }, description = "Filter by resource name (substring match)")
	protected String nameFilter;

	@Option(names = { "--content" }, description = "Include resource content (text resources only)")
	protected boolean includeContent;

	@Override
	protected Object execute(JadxDecompiler decompiler) throws Exception {
		List<ResourceInfo> results = new ArrayList<>();
		for (ResourceFile res : decompiler.getResources()) {
			if (resourceType != null) {
				try {
					ResourceType filterType = ResourceType.valueOf(resourceType.toUpperCase());
					if (res.getType() != filterType) {
						continue;
					}
				} catch (IllegalArgumentException e) {
					return JsonOutput.error("InvalidResourceType",
							"Unknown resource type: " + resourceType);
				}
			}
			if (nameFilter != null && !res.getOriginalName().contains(nameFilter)) {
				continue;
			}
			ResourceInfo info = new ResourceInfo();
			info.name = res.getOriginalName();
			info.type = res.getType().name();
			if (includeContent) {
				try {
					var container = res.loadContent();
					if (container != null) {
						info.content = container.getText().toString();
					}
				} catch (Exception e) {
					info.content = null;
				}
			}
			results.add(info);
		}
		return JsonOutput.list(results);
	}

	static class ResourceInfo {
		String name;
		String type;
		String content;
	}
}
