package view;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

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
		gbl_panelData.columnWidths = new int[] { 522 };
		gbl_panelData.rowHeights = new int[] { 211, 211, 0 };
		gbl_panelData.columnWeights = new double[] { 0.0 };
		gbl_panelData.rowWeights = new double[] { 0.0, 0.0, Double.MIN_VALUE };
		setLayout(gbl_panelData);

		GridBagConstraints gbc_panelMemory = new GridBagConstraints();
		gbc_panelMemory.anchor = GridBagConstraints.NORTHWEST;
		gbc_panelMemory.insets = new Insets(0, 0, 5, 0);
		gbc_panelMemory.gridx = 0;
		gbc_panelMemory.gridy = 0;
		add(panelMemory, gbc_panelMemory);
		
		GridBagConstraints gbc_panelRegisters = new GridBagConstraints();
		gbc_panelRegisters.anchor = GridBagConstraints.NORTHWEST;
		gbc_panelRegisters.gridx = 0;
		gbc_panelRegisters.gridy = 1;
		add(panelRegisters, gbc_panelRegisters);
	}
}
