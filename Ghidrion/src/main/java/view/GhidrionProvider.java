package view;

import docking.ComponentProvider;
import ghidrion.GhidrionPlugin;

import javax.swing.JPanel;

import ctrl.DisplayController;
import ctrl.TraceFileController;

import javax.swing.JComponent;

public class GhidrionProvider extends ComponentProvider {
	private JPanel panel;
	private GhidrionUI ui;
	private TraceFileController traceFileController;
	private DisplayController displayController;

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner) {
		super(plugin.getTool(), pluginName, owner);
		this.traceFileController = new TraceFileController(plugin);
		this.displayController = new DisplayController(plugin);
		ui = new GhidrionUI(this.traceFileController, this.displayController);

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
