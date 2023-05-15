package view;

import docking.ComponentProvider;
import ghidrion.GhidrionPlugin;
import model.MorionTraceFile;

import javax.swing.JPanel;

import ctrl.DisplayController;
import ctrl.InitTraceFileController;

import javax.swing.JComponent;

public class GhidrionProvider extends ComponentProvider {
	private JPanel panel;
	private GhidrionUI ui;
	private InitTraceFileController traceFileController;
	private DisplayController displayController;

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner, MorionTraceFile traceFile) {
		super(plugin.getTool(), pluginName, owner);
		this.traceFileController = new InitTraceFileController(plugin, traceFile);
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
