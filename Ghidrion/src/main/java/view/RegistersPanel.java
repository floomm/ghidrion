package view;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

import ctrl.TraceFileController;
import util.MemoryEntryTableModel;

public class RegistersPanel extends JPanel {
	private final TraceFileController controller;

	private final JTextField textFieldRegisterName = new JTextField();
	private final JTextField textFieldRegisterValue = new JTextField();
	private final JCheckBox chckbxIsRegisterSymbolic = new JCheckBox("");
	private final JButton btnAddRegister = new JButton("Add");
	private final JButton btnRemoveRegister = new JButton("Remove");
	private final JScrollPane scrollPaneRegisters = new JScrollPane();
	private final JTable tableRegister = new JTable();

	public RegistersPanel(TraceFileController controller) {
		this.controller = controller;
		init();
		setupComponents();
	}

	/**
	 * This constructor is solely for debugging the UI.
	 * Do NOT use for the plugin.
	 */
	public RegistersPanel() {
		this.controller = null;
		init();
	}

	private void init() {
		GridBagLayout gbl_panelRegisters = new GridBagLayout();
		gbl_panelRegisters.columnWidths = new int[] { 0, 0, 0, 0, 0, 0 };
		gbl_panelRegisters.rowHeights = new int[] { 0, 0, 50, 0 };
		gbl_panelRegisters.columnWeights = new double[] { 1.0, 1.0, 1.0, 0.0, 0.0, Double.MIN_VALUE };
		gbl_panelRegisters.rowWeights = new double[] { 0.0, 0.0, 1.0, Double.MIN_VALUE };
		setLayout(gbl_panelRegisters);

		JLabel lblRegisterName = new JLabel("Name");
		GridBagConstraints gbc_lblRegisterName = new GridBagConstraints();
		gbc_lblRegisterName.gridx = 0;
		gbc_lblRegisterName.gridy = 0;
		add(lblRegisterName, gbc_lblRegisterName);

		JLabel lblRegisterValue = new JLabel("Value");
		GridBagConstraints gbc_lblRegisterValue = new GridBagConstraints();
		gbc_lblRegisterValue.gridx = 1;
		gbc_lblRegisterValue.gridy = 0;
		add(lblRegisterValue, gbc_lblRegisterValue);

		JLabel lblIsRegisterSymbolic = new JLabel("Symbolic?");
		GridBagConstraints gbc_lblIsRegisterSymbolic = new GridBagConstraints();
		gbc_lblIsRegisterSymbolic.gridx = 2;
		gbc_lblIsRegisterSymbolic.gridy = 0;
		add(lblIsRegisterSymbolic, gbc_lblIsRegisterSymbolic);

		GridBagConstraints gbc_textFieldRegisterName = new GridBagConstraints();
		gbc_textFieldRegisterName.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldRegisterName.gridx = 0;
		gbc_textFieldRegisterName.gridy = 1;
		add(textFieldRegisterName, gbc_textFieldRegisterName);
		textFieldRegisterName.setColumns(10);

		textFieldRegisterValue.setText("0x");
		GridBagConstraints gbc_textFieldRegisterValue = new GridBagConstraints();
		gbc_textFieldRegisterValue.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldRegisterValue.gridx = 1;
		gbc_textFieldRegisterValue.gridy = 1;
		add(textFieldRegisterValue, gbc_textFieldRegisterValue);
		textFieldRegisterValue.setColumns(10);

		GridBagConstraints gbc_chckbxIsRegisterSymbolic = new GridBagConstraints();
		gbc_chckbxIsRegisterSymbolic.gridx = 2;
		gbc_chckbxIsRegisterSymbolic.gridy = 1;
		add(chckbxIsRegisterSymbolic, gbc_chckbxIsRegisterSymbolic);

		GridBagConstraints gbc_btnAddRegister = new GridBagConstraints();
		gbc_btnAddRegister.gridx = 3;
		gbc_btnAddRegister.gridy = 1;
		add(btnAddRegister, gbc_btnAddRegister);

		GridBagConstraints gbc_btnRemoveRegister = new GridBagConstraints();
		gbc_btnRemoveRegister.gridx = 4;
		gbc_btnRemoveRegister.gridy = 1;
		add(btnRemoveRegister, gbc_btnRemoveRegister);

		GridBagConstraints gbc_scrollPaneRegisters = new GridBagConstraints();
		gbc_scrollPaneRegisters.gridwidth = 5;
		gbc_scrollPaneRegisters.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneRegisters.gridx = 0;
		gbc_scrollPaneRegisters.gridy = 2;
		add(scrollPaneRegisters, gbc_scrollPaneRegisters);
	}

	private void setupComponents() {
		textFieldRegisterValue.setDocument(new HexDocument());
		scrollPaneRegisters.setViewportView(tableRegister);
		MemoryEntryTableModel tm = new MemoryEntryTableModel(controller.getTraceFile().getEntryRegisters());
		tableRegister.setModel(tm);
		tm.setColumnHeaders(tableRegister.getColumnModel());
		setupBtnAddRegister();
		setupBtnRemoveRegister();
	}

	private void setupBtnAddRegister() {
		btnAddRegister.addActionListener(e -> {
			String name = textFieldRegisterName.getText();
			String value = textFieldRegisterValue.getText();
			boolean isSymbolic = chckbxIsRegisterSymbolic.isSelected();
			controller.addEntryRegister(name, value, isSymbolic, this);
		});
	}

	private void setupBtnRemoveRegister() {
		btnRemoveRegister.addActionListener(e -> {
			controller.removeAllEntryRegisters(tableRegister);
			tableRegister.getSelectionModel().setSelectionInterval(0, 0);
		});
	}

}
