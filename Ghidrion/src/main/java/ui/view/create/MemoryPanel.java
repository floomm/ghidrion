package ui.view.create;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

import ui.ctrl.CreateController;
import ui.model.HexDocument;
import ui.model.MemoryEntryTableModel;

/**
 * Panel where the user can add memory entries to their trace file.
 */
public class MemoryPanel extends JPanel {
	private final CreateController controller;

	private final JTextField textFieldMemoryStartAddress = new JTextField();
	private final JTextField textFieldMemoryEndAddress = new JTextField();
	private final JTextField textFieldMemoryValue = new JTextField();
	private final JCheckBox chckbxIsMemorySymbolic = new JCheckBox("");
	private final JButton btnAddMemory = new JButton("Add");
	private final JButton btnRemoveMemory = new JButton("Remove");
	private final JScrollPane scrollPaneMemory = new JScrollPane();
	private final JTable tableMemory = new JTable();

	public MemoryPanel(CreateController controller) {
		this.controller = controller;
		init();
		setupComponents();
	}

	/**
	 * This constructor is solely for debugging the UI.
	 * Do NOT use for the plugin.
	 */
	public MemoryPanel() {
		this.controller = null;
		init();
	}

	private void init() {
		GridBagLayout gbl_panelMemory = new GridBagLayout();
		gbl_panelMemory.columnWidths = new int[] { 0, 0, 0, 0, 0 };
		gbl_panelMemory.rowHeights = new int[] { 0, 0, 50 };
		gbl_panelMemory.columnWeights = new double[] { 1.0, 1.0, 1.0, 1.0, Double.MIN_VALUE };
		gbl_panelMemory.rowWeights = new double[] { 0.0, 0.0, 1.0 };
		setLayout(gbl_panelMemory);

		JLabel lblMemoryStartAddress = new JLabel("Start Address");
		GridBagConstraints gbc_lblMemoryStartAddress = new GridBagConstraints();
		gbc_lblMemoryStartAddress.gridx = 0;
		gbc_lblMemoryStartAddress.gridy = 0;
		add(lblMemoryStartAddress, gbc_lblMemoryStartAddress);

		JLabel lblMemoryEndAddress = new JLabel("End Address");
		GridBagConstraints gbc_lblMemoryEndAddress = new GridBagConstraints();
		gbc_lblMemoryEndAddress.gridx = 1;
		gbc_lblMemoryEndAddress.gridy = 0;
		add(lblMemoryEndAddress, gbc_lblMemoryEndAddress);

		JLabel lblMemoryValue = new JLabel("Value");
		GridBagConstraints gbc_lblMemoryValue = new GridBagConstraints();
		gbc_lblMemoryValue.gridx = 2;
		gbc_lblMemoryValue.gridy = 0;
		add(lblMemoryValue, gbc_lblMemoryValue);

		JLabel lblIsMemorySymbolic = new JLabel("Symbolic?");
		GridBagConstraints gbc_lblIsMemorySymbolic = new GridBagConstraints();
		gbc_lblIsMemorySymbolic.gridx = 3;
		gbc_lblIsMemorySymbolic.gridy = 0;
		add(lblIsMemorySymbolic, gbc_lblIsMemorySymbolic);

		textFieldMemoryStartAddress.setText("0x");
		GridBagConstraints gbc_textFieldMemoryStartAddress = new GridBagConstraints();
		gbc_textFieldMemoryStartAddress.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldMemoryStartAddress.gridx = 0;
		gbc_textFieldMemoryStartAddress.gridy = 1;
		add(textFieldMemoryStartAddress, gbc_textFieldMemoryStartAddress);
		textFieldMemoryStartAddress.setColumns(10);

		textFieldMemoryEndAddress.setText("0x");
		GridBagConstraints gbc_textFieldMemoryEndAddress = new GridBagConstraints();
		gbc_textFieldMemoryEndAddress.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldMemoryEndAddress.gridx = 1;
		gbc_textFieldMemoryEndAddress.gridy = 1;
		add(textFieldMemoryEndAddress, gbc_textFieldMemoryEndAddress);
		textFieldMemoryEndAddress.setColumns(10);

		textFieldMemoryValue.setText("0x");
		GridBagConstraints gbc_textFieldMemoryValue = new GridBagConstraints();
		gbc_textFieldMemoryValue.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldMemoryValue.gridx = 2;
		gbc_textFieldMemoryValue.gridy = 1;
		add(textFieldMemoryValue, gbc_textFieldMemoryValue);
		textFieldMemoryValue.setColumns(10);

		GridBagConstraints gbc_chckbxIsMemorySymbolic = new GridBagConstraints();
		gbc_chckbxIsMemorySymbolic.gridx = 3;
		gbc_chckbxIsMemorySymbolic.gridy = 1;
		add(chckbxIsMemorySymbolic, gbc_chckbxIsMemorySymbolic);

		GridBagConstraints gbc_btnAddMemory = new GridBagConstraints();
		gbc_btnAddMemory.gridx = 4;
		gbc_btnAddMemory.gridy = 1;
		add(btnAddMemory, gbc_btnAddMemory);

		GridBagConstraints gbc_btnRemoveMemory = new GridBagConstraints();
		gbc_btnRemoveMemory.gridx = 4;
		gbc_btnRemoveMemory.gridy = 2;
		add(btnRemoveMemory, gbc_btnRemoveMemory);

		GridBagConstraints gbc_scrollPaneMemory = new GridBagConstraints();
		gbc_scrollPaneMemory.gridwidth = 4;
		gbc_scrollPaneMemory.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneMemory.gridx = 0;
		gbc_scrollPaneMemory.gridy = 2;
		add(scrollPaneMemory, gbc_scrollPaneMemory);

	}

	private void setupComponents() {
		textFieldMemoryStartAddress.setDocument(new HexDocument(HexDocument.MAX_HEX_DIGITS_MEMORY_ADDRESS));
		textFieldMemoryEndAddress.setDocument(new HexDocument(HexDocument.MAX_HEX_DIGITS_MEMORY_ADDRESS));
		textFieldMemoryValue.setDocument(new HexDocument(HexDocument.MAX_HEX_DIGITS_UNLIMITED));
		scrollPaneMemory.setViewportView(tableMemory);
		MemoryEntryTableModel tm = new MemoryEntryTableModel(controller.getTraceFile().getEntryMemory());
		tableMemory.setModel(tm);
		tm.setColumnHeaders(tableMemory.getColumnModel());
		setupBtnAddMemory();
		setupBtnRemoveMemory();
	}

	private void setupBtnAddMemory() {
		btnAddMemory.addActionListener(e -> {
			String startAddress = textFieldMemoryStartAddress.getText();
			String endAddress = textFieldMemoryEndAddress.getText();
			String value = textFieldMemoryValue.getText();
			boolean isSymbolic = chckbxIsMemorySymbolic.isSelected();
			controller.addEntryMemory(startAddress, endAddress, value, isSymbolic, this);
		});
	}

	private void setupBtnRemoveMemory() {
		btnRemoveMemory.addActionListener(e -> {
			controller.removeAllEntryMemory(tableMemory);
			if (tableMemory.getRowCount() > 0)
				tableMemory.getSelectionModel().setSelectionInterval(0, 0);
		});
	}

}
