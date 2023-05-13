package view;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import javax.swing.JPanel;

import ctrl.TraceFileController;

public class DataPanel extends JPanel {
	private final MemoryPanel panelMemory;
	private final RegistersPanel panelRegisters;

	public DataPanel(TraceFileController controller) {
		this.panelMemory = new MemoryPanel(controller);
		this.panelRegisters = new RegistersPanel(controller);
		init();
	}

	/**
	 * This constructor is solely for debugging the UI.
	 * Do NOT use for the plugin.
	 */
	public DataPanel() {
		this.panelMemory = new MemoryPanel();
		this.panelRegisters = new RegistersPanel();
		init();
	}

	private void init() {
		GridBagLayout gbl_panelData = new GridBagLayout();
		gbl_panelData.columnWidths = new int[] { 1, 1 };
		gbl_panelData.rowHeights = new int[] { 1 };
		gbl_panelData.columnWeights = new double[] { 1.0, 1.0 };
		gbl_panelData.rowWeights = new double[] { 1.0 };
		setLayout(gbl_panelData);

		GridBagConstraints gbc_panelMemory = new GridBagConstraints();
		gbc_panelMemory.gridx = 0;
		gbc_panelMemory.gridy = 0;
		add(panelMemory, gbc_panelMemory);

		GridBagConstraints gbc_panelRegisters = new GridBagConstraints();
		gbc_panelRegisters.gridx = 1;
		gbc_panelRegisters.gridy = 0;
		add(panelRegisters, gbc_panelRegisters);
	}
}
