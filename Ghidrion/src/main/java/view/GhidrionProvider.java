package view;

import docking.ComponentProvider;
import ghidrion.GhidrionPlugin;

import javax.swing.JPanel;

import ctrl.DisplayTraceFileController;
import ctrl.TraceFileController;

import javax.swing.JComponent;

public class GhidrionProvider extends ComponentProvider {
	private JPanel panel;
	private GhidrionUI ui;
	private TraceFileController traceFileController;
	private DisplayTraceFileController displayTraceFileController;

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner) {
		super(plugin.getTool(), pluginName, owner);
		this.traceFileController = new TraceFileController(plugin);
		this.displayTraceFileController = new DisplayTraceFileController(plugin);
		ui = new GhidrionUI(this.traceFileController, this.displayTraceFileController);

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
