package view;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.border.TitledBorder;

import ctrl.TraceFileController;
import util.MemoryEntryTableModel;

public class MemoryPanel extends JPanel {
	private final TraceFileController controller;

	private final JTextField textFieldMemoryAddress = new JTextField();
	private final JTextField textFieldMemoryValue = new JTextField();
	private final JCheckBox chckbxIsMemorySymbolic = new JCheckBox("");
	private final JButton btnAddMemory = new JButton("Add");
	private final JButton btnRemoveMemory = new JButton("Remove");
	private final JScrollPane scrollPaneMemory = new JScrollPane();
	private final JTable tableMemory = new JTable();

	public MemoryPanel(TraceFileController controller) {
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
		setBorder(new TitledBorder(null, "Add memory", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagLayout gbl_panelMemory = new GridBagLayout();
		gbl_panelMemory.columnWidths = new int[] { 0, 0, 0, 0, 0, 0 };
		gbl_panelMemory.rowHeights = new int[] { 0, 0, 50, 0 };
		gbl_panelMemory.columnWeights = new double[] { 1.0, 1.0, 1.0, 0.0, 0.0, Double.MIN_VALUE };
		gbl_panelMemory.rowWeights = new double[] { 0.0, 0.0, 1.0, Double.MIN_VALUE };
		setLayout(gbl_panelMemory);

		JLabel lblMemoryAddress = new JLabel("Address");
		GridBagConstraints gbc_lblMemoryAddress = new GridBagConstraints();
		gbc_lblMemoryAddress.insets = new Insets(0, 0, 5, 5);
		gbc_lblMemoryAddress.gridx = 0;
		gbc_lblMemoryAddress.gridy = 0;
		add(lblMemoryAddress, gbc_lblMemoryAddress);

		JLabel lblMemoryValue = new JLabel("Value");
		GridBagConstraints gbc_lblMemoryValue = new GridBagConstraints();
		gbc_lblMemoryValue.insets = new Insets(0, 0, 5, 5);
		gbc_lblMemoryValue.gridx = 1;
		gbc_lblMemoryValue.gridy = 0;
		add(lblMemoryValue, gbc_lblMemoryValue);

		JLabel lblIsMemorySymbolic = new JLabel("Symbolic?");
		GridBagConstraints gbc_lblIsMemorySymbolic = new GridBagConstraints();
		gbc_lblIsMemorySymbolic.insets = new Insets(0, 0, 5, 5);
		gbc_lblIsMemorySymbolic.gridx = 2;
		gbc_lblIsMemorySymbolic.gridy = 0;
		add(lblIsMemorySymbolic, gbc_lblIsMemorySymbolic);

		textFieldMemoryAddress.setText("0x");
		GridBagConstraints gbc_textFieldMemoryAddress = new GridBagConstraints();
		gbc_textFieldMemoryAddress.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldMemoryAddress.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldMemoryAddress.gridx = 0;
		gbc_textFieldMemoryAddress.gridy = 1;
		add(textFieldMemoryAddress, gbc_textFieldMemoryAddress);
		textFieldMemoryAddress.setColumns(10);

		textFieldMemoryValue.setText("0x");
		GridBagConstraints gbc_textFieldMemoryValue = new GridBagConstraints();
		gbc_textFieldMemoryValue.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldMemoryValue.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldMemoryValue.gridx = 1;
		gbc_textFieldMemoryValue.gridy = 1;
		add(textFieldMemoryValue, gbc_textFieldMemoryValue);
		textFieldMemoryValue.setColumns(10);

		GridBagConstraints gbc_chckbxIsMemorySymbolic = new GridBagConstraints();
		gbc_chckbxIsMemorySymbolic.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxIsMemorySymbolic.gridx = 2;
		gbc_chckbxIsMemorySymbolic.gridy = 1;
		add(chckbxIsMemorySymbolic, gbc_chckbxIsMemorySymbolic);

		GridBagConstraints gbc_btnAddMemory = new GridBagConstraints();
		gbc_btnAddMemory.insets = new Insets(0, 0, 5, 5);
		gbc_btnAddMemory.gridx = 3;
		gbc_btnAddMemory.gridy = 1;
		add(btnAddMemory, gbc_btnAddMemory);

		GridBagConstraints gbc_btnRemoveMemory = new GridBagConstraints();
		gbc_btnRemoveMemory.insets = new Insets(0, 0, 5, 0);
		gbc_btnRemoveMemory.gridx = 4;
		gbc_btnRemoveMemory.gridy = 1;
		add(btnRemoveMemory, gbc_btnRemoveMemory);

		GridBagConstraints gbc_scrollPaneMemory = new GridBagConstraints();
		gbc_scrollPaneMemory.gridwidth = 5;
		gbc_scrollPaneMemory.insets = new Insets(0, 0, 0, 5);
		gbc_scrollPaneMemory.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneMemory.gridx = 0;
		gbc_scrollPaneMemory.gridy = 2;
		add(scrollPaneMemory, gbc_scrollPaneMemory);
	}

	private void setupComponents() {
		textFieldMemoryAddress.setDocument(new HexDocument());
		textFieldMemoryValue.setDocument(new HexDocument());
		scrollPaneMemory.setViewportView(tableMemory);
		MemoryEntryTableModel tm = new MemoryEntryTableModel(controller.getTraceFile().getEntryMemory());
		tableMemory.setModel(tm);
		tm.setColumnHeaders(tableMemory.getColumnModel());
		setupBtnAddMemory();
		setupBtnRemoveMemory();
	}

	private void setupBtnAddMemory() {
		btnAddMemory.addActionListener(e -> {
			String address = textFieldMemoryAddress.getText();
			String value = textFieldMemoryValue.getText();
			boolean isSymbolic = chckbxIsMemorySymbolic.isSelected();
			controller.addEntryMemory(address, value, isSymbolic);
		});
	}

	private void setupBtnRemoveMemory() {
		btnRemoveMemory.addActionListener(e -> {
			controller.removeAllEntryMemory(tableMemory);
			tableMemory.getSelectionModel().setSelectionInterval(0, 0);
		});
	}

}
