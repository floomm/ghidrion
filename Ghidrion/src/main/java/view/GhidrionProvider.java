package view;

import ctrl.TraceFileController;
import docking.ComponentProvider;
import ghidrion.GhidrionPlugin;

import javax.swing.JPanel;
import javax.swing.JComponent;

public class GhidrionProvider extends ComponentProvider {
	private JPanel panel;
	private GhidrionUI ui;

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner) {
		super(plugin.getTool(), pluginName, owner);
		ui = new GhidrionUI(plugin, new TraceFileController(plugin));

		buildPanel();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel();
		panel.add(ui.getTabbedPane());
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
