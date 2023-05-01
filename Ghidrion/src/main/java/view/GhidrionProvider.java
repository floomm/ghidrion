package view;

import java.awt.GridLayout;

import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;

import docking.ComponentProvider;
import ghidrion.GhidrionPlugin;

public class GhidrionProvider extends ComponentProvider {

	private GhidrionPlugin plugin;
	
	private JPanel panel;
	private CreateTraceFilePanel createTraceFilePanel = new CreateTraceFilePanel();
	private JPanel traceExecutionPanel = new JPanel();
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
		panel = new JPanel(new GridLayout(3, 0));
		GroupLayout panelGL = new javax.swing.GroupLayout(panel);
		panelGL.setHorizontalGroup(panelGL.createParallelGroup(Alignment.LEADING)
				.addGroup(panelGL.createSequentialGroup()
						.addContainerGap()
						.addComponent(createTraceFilePanel, GroupLayout.DEFAULT_SIZE, 256, Short.MAX_VALUE)
						.addGap(24))
				.addGroup(panelGL.createSequentialGroup()
						.addContainerGap()
						.addComponent(traceExecutionPanel, GroupLayout.DEFAULT_SIZE, 256, Short.MAX_VALUE)
						.addGap(24))
				.addGroup(panelGL.createSequentialGroup()
						.addContainerGap()
						.addComponent(displayTracePanel, GroupLayout.DEFAULT_SIZE, 256, Short.MAX_VALUE)
						.addGap(24))
				);
		
		panelGL.setVerticalGroup(panelGL.createParallelGroup(Alignment.LEADING)
				.addGroup(panelGL.createSequentialGroup()
						.addContainerGap()
						.addComponent(createTraceFilePanel, GroupLayout.DEFAULT_SIZE, 256, Short.MAX_VALUE)
						.addGap(24))
				.addGroup(panelGL.createSequentialGroup()
						.addContainerGap()
						.addComponent(traceExecutionPanel, GroupLayout.DEFAULT_SIZE, 256, Short.MAX_VALUE)
						.addGap(24))
				.addGroup(panelGL.createSequentialGroup()
						.addContainerGap()
						.addComponent(displayTracePanel, GroupLayout.DEFAULT_SIZE, 256, Short.MAX_VALUE)
						.addGap(24))
				);
		
		TitledBorder createTraceFilePanelBorder = BorderFactory.createTitledBorder("Create init trace file");
		createTraceFilePanel.setBorder(createTraceFilePanelBorder);
		panel.add(createTraceFilePanel);
		
		TitledBorder traceExecutionPanelBorder = BorderFactory.createTitledBorder("Trace execution");
		traceExecutionPanel.setBorder(traceExecutionPanelBorder);
		panel.add(traceExecutionPanel);

		TitledBorder displayTracePanelBorder = BorderFactory.createTitledBorder("Display Morion trace file");
		displayTracePanel.setBorder(displayTracePanelBorder);
		panel.add(displayTracePanel);
		
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
