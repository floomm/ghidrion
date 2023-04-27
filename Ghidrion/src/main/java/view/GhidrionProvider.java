package view;

import java.awt.GridLayout;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.ComponentProvider;
import ghidrion.GhidrionPlugin;

public class GhidrionProvider extends ComponentProvider {

	private GhidrionPlugin plugin;
	
	private JPanel panel;
	private CreateTraceFilePanel createTraceFilePanel = new CreateTraceFilePanel();
	private DisplayTracePanel displayTracePanel = new DisplayTracePanel();

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner) {
		super(plugin.getTool(), pluginName, owner);
		this.plugin = plugin;

		buildPanel();
	}
	
	public void init() {
		displayTracePanel.init(plugin);
		createTraceFilePanel.init();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new GridLayout(6, 1));
		panel.add(new JLabel("Create a Morion trace file"));
		panel.add(createTraceFilePanel);
		panel.add(new JLabel("Trace an execution"));
		panel.add(new JPanel());
		panel.add(new JLabel("Display Morion trace file"));
		panel.add(displayTracePanel);
		
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
