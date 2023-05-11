package view;

import docking.ComponentProvider;
import ghidrion.GhidrionPlugin;

import javax.swing.JPanel;

import ctrl.DisplayController;
import ctrl.CreateController;

import javax.swing.JComponent;

public class GhidrionProvider extends ComponentProvider {
	private JPanel panel;
	private GhidrionUI ui;
	private CreateController createController;
	private DisplayController displayController;

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner) {
		super(plugin.getTool(), pluginName, owner);
		this.createController = new CreateController(plugin);
		this.displayController = new DisplayController(plugin);
		ui = new GhidrionUI(this.createController, this.displayController);

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
