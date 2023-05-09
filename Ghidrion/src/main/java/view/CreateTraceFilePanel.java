package view;

import javax.swing.JPanel;
import javax.swing.border.TitledBorder;

import ctrl.TraceFileController;
import ghidrion.GhidrionPlugin;
import model.MemoryEntry;
import model.MorionTraceFile;

import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.util.stream.Collectors;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.DefaultListModel;
import javax.swing.JCheckBox;
import javax.swing.JScrollPane;
import javax.swing.JList;
import javax.swing.JTabbedPane;

public class CreateTraceFilePanel extends JPanel {
	private final MorionTraceFile traceFile;

	protected final HookPanel panelHooks;
	protected JTextField textFieldRegisterName;
	protected JTextField textFieldRegisterValue;
	protected JCheckBox chckbxIsRegisterSymbolic = new JCheckBox("");
	protected JButton btnAddRegister = new JButton("Add");
	protected JButton btnRemoveRegister = new JButton("Remove");
	protected JScrollPane scrollPaneRegisters = new JScrollPane();
	protected JTextField textFieldMemoryAddress;
	protected JTextField textFieldMemoryValue;
	protected JCheckBox chckbxIsMemorySymbolic = new JCheckBox("");
	protected JButton btnAddMemory = new JButton("Add");
	protected JButton btnRemoveMemory = new JButton("Remove");
	protected JScrollPane scrollPaneMemory = new JScrollPane();
	protected JButton btnLoadTraceFile = new JButton("Load");
	protected JButton btnCreateTraceFile = new JButton("Save As");
	protected JButton btnClearTraceFile = new JButton("Clear");
	protected final JList<MemoryEntry> registerList = new JList<>();
	protected final JList<MemoryEntry> memoryList = new JList<>();
	private final JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
	private final JPanel panelData = new JPanel();

	public CreateTraceFilePanel(GhidrionPlugin plugin, MorionTraceFile traceFile) {
		this.traceFile = traceFile;

		GridBagLayout gbl_panelCreateTraceFile = new GridBagLayout();
		gbl_panelCreateTraceFile.columnWidths = new int[] { 956, 0 };
		gbl_panelCreateTraceFile.rowHeights = new int[] { 0, 0, 0, 0, 0, 0, 0 };
		gbl_panelCreateTraceFile.columnWeights = new double[] { 1.0, Double.MIN_VALUE };
		gbl_panelCreateTraceFile.rowWeights = new double[] { 1.0, 0.0, 0.0, 1.0, 1.0, 1.0, Double.MIN_VALUE };
		setLayout(gbl_panelCreateTraceFile);

		JPanel panelButtons = new JPanel();
		GridBagConstraints gbc_panelButtons = new GridBagConstraints();
		gbc_panelButtons.insets = new Insets(0, 0, 5, 0);
		gbc_panelButtons.fill = GridBagConstraints.BOTH;
		gbc_panelButtons.gridx = 0;
		gbc_panelButtons.gridy = 1;
		this.add(panelButtons, gbc_panelButtons);

		panelButtons.add(btnLoadTraceFile);

		panelButtons.add(btnCreateTraceFile);

		panelButtons.add(btnClearTraceFile);

		GridBagConstraints gbc_tabbedPane = new GridBagConstraints();
		gbc_tabbedPane.insets = new Insets(0, 0, 5, 0);
		gbc_tabbedPane.fill = GridBagConstraints.BOTH;
		gbc_tabbedPane.gridx = 0;
		gbc_tabbedPane.gridy = 0;
		add(tabbedPane, gbc_tabbedPane);
		this.panelHooks = new HookPanel(plugin, traceFile);
		tabbedPane.addTab("Hooks", null, panelHooks, null);
		GridBagLayout gbl_panelData = new GridBagLayout();
		gbl_panelData.columnWidths = new int[] { 522, 0 };
		gbl_panelData.rowHeights = new int[] { 211, 211, 0 };
		gbl_panelData.columnWeights = new double[] { 0.0, Double.MIN_VALUE };
		gbl_panelData.rowWeights = new double[] { 0.0, 0.0, Double.MIN_VALUE };
		tabbedPane.addTab("Data", null, panelData, null);
		panelData.setLayout(gbl_panelData);

		JPanel panelMemory = new JPanel();
		GridBagConstraints gbc_panelMemory = new GridBagConstraints();
		gbc_panelMemory.anchor = GridBagConstraints.NORTHWEST;
		gbc_panelMemory.insets = new Insets(0, 0, 5, 0);
		gbc_panelMemory.gridx = 0;
		gbc_panelMemory.gridy = 0;
		panelData.add(panelMemory, gbc_panelMemory);
		panelMemory.setBorder(new TitledBorder(null, "Add memory", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagLayout gbl_panelMemory = new GridBagLayout();
		gbl_panelMemory.columnWidths = new int[] { 0, 0, 0, 0, 0, 0 };
		gbl_panelMemory.rowHeights = new int[] { 0, 0, 50, 0 };
		gbl_panelMemory.columnWeights = new double[] { 1.0, 1.0, 1.0, 0.0, 0.0, Double.MIN_VALUE };
		gbl_panelMemory.rowWeights = new double[] { 0.0, 0.0, 1.0, Double.MIN_VALUE };
		panelMemory.setLayout(gbl_panelMemory);

		JLabel lblMemoryAddress = new JLabel("Address");
		GridBagConstraints gbc_lblMemoryAddress = new GridBagConstraints();
		gbc_lblMemoryAddress.insets = new Insets(0, 0, 5, 5);
		gbc_lblMemoryAddress.gridx = 0;
		gbc_lblMemoryAddress.gridy = 0;
		panelMemory.add(lblMemoryAddress, gbc_lblMemoryAddress);

		JLabel lblMemoryValue = new JLabel("Value");
		GridBagConstraints gbc_lblMemoryValue = new GridBagConstraints();
		gbc_lblMemoryValue.insets = new Insets(0, 0, 5, 5);
		gbc_lblMemoryValue.gridx = 1;
		gbc_lblMemoryValue.gridy = 0;
		panelMemory.add(lblMemoryValue, gbc_lblMemoryValue);

		JLabel lblIsMemorySymbolic = new JLabel("Symbolic?");
		GridBagConstraints gbc_lblIsMemorySymbolic = new GridBagConstraints();
		gbc_lblIsMemorySymbolic.insets = new Insets(0, 0, 5, 5);
		gbc_lblIsMemorySymbolic.gridx = 2;
		gbc_lblIsMemorySymbolic.gridy = 0;
		panelMemory.add(lblIsMemorySymbolic, gbc_lblIsMemorySymbolic);

		textFieldMemoryAddress = new JTextField();
		textFieldMemoryAddress.setText("0x");
		GridBagConstraints gbc_textFieldMemoryAddress = new GridBagConstraints();
		gbc_textFieldMemoryAddress.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldMemoryAddress.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldMemoryAddress.gridx = 0;
		gbc_textFieldMemoryAddress.gridy = 1;
		panelMemory.add(textFieldMemoryAddress, gbc_textFieldMemoryAddress);
		textFieldMemoryAddress.setColumns(10);

		textFieldMemoryValue = new JTextField();
		textFieldMemoryValue.setText("0x");
		GridBagConstraints gbc_textFieldMemoryValue = new GridBagConstraints();
		gbc_textFieldMemoryValue.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldMemoryValue.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldMemoryValue.gridx = 1;
		gbc_textFieldMemoryValue.gridy = 1;
		panelMemory.add(textFieldMemoryValue, gbc_textFieldMemoryValue);
		textFieldMemoryValue.setColumns(10);

		GridBagConstraints gbc_chckbxIsMemorySymbolic = new GridBagConstraints();
		gbc_chckbxIsMemorySymbolic.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxIsMemorySymbolic.gridx = 2;
		gbc_chckbxIsMemorySymbolic.gridy = 1;
		panelMemory.add(chckbxIsMemorySymbolic, gbc_chckbxIsMemorySymbolic);

		GridBagConstraints gbc_btnAddMemory = new GridBagConstraints();
		gbc_btnAddMemory.insets = new Insets(0, 0, 5, 5);
		gbc_btnAddMemory.gridx = 3;
		gbc_btnAddMemory.gridy = 1;
		panelMemory.add(btnAddMemory, gbc_btnAddMemory);

		GridBagConstraints gbc_btnRemoveMemory = new GridBagConstraints();
		gbc_btnRemoveMemory.insets = new Insets(0, 0, 5, 0);
		gbc_btnRemoveMemory.gridx = 4;
		gbc_btnRemoveMemory.gridy = 1;
		panelMemory.add(btnRemoveMemory, gbc_btnRemoveMemory);

		GridBagConstraints gbc_scrollPaneMemory = new GridBagConstraints();
		gbc_scrollPaneMemory.gridwidth = 5;
		gbc_scrollPaneMemory.insets = new Insets(0, 0, 0, 5);
		gbc_scrollPaneMemory.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneMemory.gridx = 0;
		gbc_scrollPaneMemory.gridy = 2;
		panelMemory.add(scrollPaneMemory, gbc_scrollPaneMemory);

		JPanel panelRegisters = new JPanel();
		GridBagConstraints gbc_panelRegisters = new GridBagConstraints();
		gbc_panelRegisters.anchor = GridBagConstraints.NORTHWEST;
		gbc_panelRegisters.gridx = 0;
		gbc_panelRegisters.gridy = 1;
		panelData.add(panelRegisters, gbc_panelRegisters);
		panelRegisters
				.setBorder(new TitledBorder(null, "Add register", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagLayout gbl_panelRegisters = new GridBagLayout();
		gbl_panelRegisters.columnWidths = new int[] { 0, 0, 0, 0, 0, 0 };
		gbl_panelRegisters.rowHeights = new int[] { 0, 0, 50, 0 };
		gbl_panelRegisters.columnWeights = new double[] { 1.0, 1.0, 1.0, 0.0, 0.0, Double.MIN_VALUE };
		gbl_panelRegisters.rowWeights = new double[] { 0.0, 0.0, 1.0, Double.MIN_VALUE };
		panelRegisters.setLayout(gbl_panelRegisters);

		JLabel lblRegisterName = new JLabel("Name");
		GridBagConstraints gbc_lblRegisterName = new GridBagConstraints();
		gbc_lblRegisterName.insets = new Insets(0, 0, 5, 5);
		gbc_lblRegisterName.gridx = 0;
		gbc_lblRegisterName.gridy = 0;
		panelRegisters.add(lblRegisterName, gbc_lblRegisterName);

		JLabel lblRegisterValue = new JLabel("Value");
		GridBagConstraints gbc_lblRegisterValue = new GridBagConstraints();
		gbc_lblRegisterValue.insets = new Insets(0, 0, 5, 5);
		gbc_lblRegisterValue.gridx = 1;
		gbc_lblRegisterValue.gridy = 0;
		panelRegisters.add(lblRegisterValue, gbc_lblRegisterValue);

		JLabel lblIsRegisterSymbolic = new JLabel("Symbolic?");
		GridBagConstraints gbc_lblIsRegisterSymbolic = new GridBagConstraints();
		gbc_lblIsRegisterSymbolic.insets = new Insets(0, 0, 5, 5);
		gbc_lblIsRegisterSymbolic.gridx = 2;
		gbc_lblIsRegisterSymbolic.gridy = 0;
		panelRegisters.add(lblIsRegisterSymbolic, gbc_lblIsRegisterSymbolic);

		textFieldRegisterName = new JTextField();
		GridBagConstraints gbc_textFieldRegisterName = new GridBagConstraints();
		gbc_textFieldRegisterName.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldRegisterName.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldRegisterName.gridx = 0;
		gbc_textFieldRegisterName.gridy = 1;
		panelRegisters.add(textFieldRegisterName, gbc_textFieldRegisterName);
		textFieldRegisterName.setColumns(10);

		textFieldRegisterValue = new JTextField();
		textFieldRegisterValue.setText("0x");
		GridBagConstraints gbc_textFieldRegisterValue = new GridBagConstraints();
		gbc_textFieldRegisterValue.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldRegisterValue.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldRegisterValue.gridx = 1;
		gbc_textFieldRegisterValue.gridy = 1;
		panelRegisters.add(textFieldRegisterValue, gbc_textFieldRegisterValue);
		textFieldRegisterValue.setColumns(10);

		GridBagConstraints gbc_chckbxIsRegisterSymbolic = new GridBagConstraints();
		gbc_chckbxIsRegisterSymbolic.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxIsRegisterSymbolic.gridx = 2;
		gbc_chckbxIsRegisterSymbolic.gridy = 1;
		panelRegisters.add(chckbxIsRegisterSymbolic, gbc_chckbxIsRegisterSymbolic);

		GridBagConstraints gbc_btnAddRegister = new GridBagConstraints();
		gbc_btnAddRegister.insets = new Insets(0, 0, 5, 5);
		gbc_btnAddRegister.gridx = 3;
		gbc_btnAddRegister.gridy = 1;
		panelRegisters.add(btnAddRegister, gbc_btnAddRegister);

		GridBagConstraints gbc_btnRemoveRegister = new GridBagConstraints();
		gbc_btnRemoveRegister.insets = new Insets(0, 0, 5, 0);
		gbc_btnRemoveRegister.gridx = 4;
		gbc_btnRemoveRegister.gridy = 1;
		panelRegisters.add(btnRemoveRegister, gbc_btnRemoveRegister);

		GridBagConstraints gbc_scrollPaneRegisters = new GridBagConstraints();
		gbc_scrollPaneRegisters.gridwidth = 5;
		gbc_scrollPaneRegisters.insets = new Insets(0, 0, 0, 5);
		gbc_scrollPaneRegisters.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneRegisters.gridx = 0;
		gbc_scrollPaneRegisters.gridy = 2;
		panelRegisters.add(scrollPaneRegisters, gbc_scrollPaneRegisters);

		setupComponents();
	}

	private void setupComponents() {
		textFieldRegisterValue.setDocument(new HexDocument());
		textFieldMemoryAddress.setDocument(new HexDocument());
		textFieldMemoryValue.setDocument(new HexDocument());

		setupListRegister();
		setupBtnAddRegister();
		setupBtnRemoveRegister();
		scrollPaneRegisters.setViewportView(registerList);

		setupListMemory();
		setupBtnAddMemory();
		setupBtnRemoveMemory();
		scrollPaneMemory.setViewportView(memoryList);

		setupBtnLoadTraceFile();
		setupBtnCreateTraceFile();
		setupBtnClearTraceFile();
	}

	private void setupListRegister() {
		traceFile.getEntryRegistersObservable().addObserver(newList -> {
			DefaultListModel<MemoryEntry> listModel = new DefaultListModel<>();
			listModel.addAll(newList.stream().sorted().collect(Collectors.toList()));
			this.registerList.setModel(listModel);
		});
	}

	private void setupBtnAddRegister() {
		btnAddRegister.addActionListener(e -> {
			String name = textFieldRegisterName.getText();
			String value = textFieldRegisterValue.getText();
			boolean isSymbolic = chckbxIsRegisterSymbolic.isSelected();
			traceFile.addEntryStateRegister(new MemoryEntry(name, value, isSymbolic));
		});
	}

	private void setupBtnRemoveRegister() {
		btnRemoveRegister.addActionListener(e -> {
			traceFile.removeEntryRegisters(registerList.getSelectedValuesList());
			registerList.setSelectedIndex(0);
		});
	}

	private void setupListMemory() {
		traceFile.getEntryMemoryObservable().addObserver(newList -> {
			DefaultListModel<MemoryEntry> listModel = new DefaultListModel<>();
			listModel.addAll(newList.stream().sorted().collect(Collectors.toList()));
			this.memoryList.setModel(listModel);
		});
	}

	private void setupBtnAddMemory() {
		btnAddMemory.addActionListener(e -> {
			String address = textFieldMemoryAddress.getText();
			String value = textFieldMemoryValue.getText();
			boolean isSymbolic = chckbxIsMemorySymbolic.isSelected();
			traceFile.addEntryStateMemory(new MemoryEntry(address, value, isSymbolic));
		});
	}

	private void setupBtnRemoveMemory() {
		btnRemoveMemory.addActionListener(e -> {
			traceFile.removeEntryMemoryEntries(memoryList.getSelectedValuesList());
			memoryList.setSelectedIndex(0);
		});
	}

	private void setupBtnLoadTraceFile() {
		btnLoadTraceFile.addActionListener(e -> {
			clearTraceFile();
		});
	}

	private void setupBtnCreateTraceFile() {
		btnCreateTraceFile.addActionListener(e -> TraceFileController.writeTraceFile(this, traceFile));
	}

	private void setupBtnClearTraceFile() {
		btnClearTraceFile.addActionListener(e -> clearTraceFile());
	}

	private void clearTraceFile() {
		// Clear registers
		textFieldRegisterName.setText("");
		textFieldRegisterValue.setDocument(new HexDocument());
		chckbxIsRegisterSymbolic.setSelected(false);

		// Clear memory
		textFieldMemoryAddress.setDocument(new HexDocument());
		textFieldMemoryValue.setDocument(new HexDocument());
		chckbxIsMemorySymbolic.setSelected(false);

		// Clear data structure
		traceFile.clear();
	}
}
