package ctrl;

import ghidrion.GhidrionPlugin;

public class DisplayController {
	private final GhidrionPlugin plugin;

	public DisplayController(GhidrionPlugin plugin) {
		this.plugin = plugin;
	}
	
	public GhidrionPlugin getPlugin() {
		return plugin;
	}

}
