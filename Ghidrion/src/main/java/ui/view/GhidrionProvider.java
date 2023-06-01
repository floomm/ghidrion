package ui.view;

import docking.ComponentProvider;
import ghidrion.GhidrionPlugin;
import model.MorionInitTraceFile;
import ui.ctrl.CreateController;
import ui.ctrl.DisplayController;

import javax.swing.JPanel;
import javax.swing.JComponent;

/**
 * Initializes the plugin UI.
 */
public class GhidrionProvider extends ComponentProvider {
	private JPanel panel = new JPanel();

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner, MorionInitTraceFile traceFile) {
		super(plugin.getTool(), pluginName, owner);
		GhidrionUI ui = new GhidrionUI(new CreateController(plugin, traceFile), new DisplayController(plugin));
		panel.add(ui.getPanel());
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
