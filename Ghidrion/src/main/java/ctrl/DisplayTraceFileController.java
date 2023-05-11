package ctrl;

import ghidrion.GhidrionPlugin;

public class DisplayTraceFileController {
	private final GhidrionPlugin plugin;

	public DisplayTraceFileController(GhidrionPlugin plugin) {
		this.plugin = plugin;
	}
	
	public GhidrionPlugin getPlugin() {
		return plugin;
	}

}
