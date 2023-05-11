package view;

import docking.ComponentProvider;
import ghidrion.GhidrionPlugin;
import model.MorionTraceFile;

import javax.swing.JPanel;
import javax.swing.JComponent;

public class GhidrionProvider extends ComponentProvider {
	private final GhidrionUI ui;
	private JPanel panel;

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner) {
		super(plugin.getTool(), pluginName, owner);
		ui = new GhidrionUI(plugin, new MorionTraceFile());

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
