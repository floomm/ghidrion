package view;

import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;

import ctrl.TraceFileController;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrion.FunctionHelper;
import ghidrion.GhidrionPlugin;

import javax.swing.border.EtchedBorder;
import java.awt.Color;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListModel;
import javax.swing.JCheckBox;
import javax.swing.JScrollPane;
import javax.swing.JList;
import javax.swing.ListSelectionModel;

public class CreateTraceFilePanel extends JPanel {
	private GhidrionPlugin plugin;
	private final TraceFileController traceFileController;
	private FunctionHelper functionHelper;
	
	protected final JPanel panelHooks = new JPanel();
	protected final JLabel lblFunctionNamed = new JLabel("Block Name");
	protected final JLabel lblFunctionName = new JLabel("Function Name");
	protected final JLabel lblFunctionAddress = new JLabel("Function Address");
	protected final JList<String> listBlockName = new JList<>();
	protected final JList<Address> listFunctionAddress = new JList<>();
	protected final JLabel lblMode = new JLabel("Mode");
	protected final JComboBox<String> comboBoxHookMode = new JComboBox<>();
	protected final JButton btnAddHook = new JButton("Add");
	protected final JList<String> listFunctionName = new JList<String>();
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
	private final DefaultListModel<List<String>> registerListModel = new DefaultListModel<>();
	private final JList<List<String>> registerList = new JList<>(registerListModel);
	private final DefaultListModel<List<String>> memoryListModel = new DefaultListModel<>();
	private final JList<List<String>> memoryList = new JList<>(memoryListModel);
	
	public CreateTraceFilePanel(GhidrionPlugin plugin, TraceFileController traceFileController) {
		this.plugin = plugin;
		this.traceFileController = traceFileController;
		
		setBorder(new TitledBorder(
				new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)),
				"Create init trace file", TitledBorder.LEADING, TitledBorder.ABOVE_TOP, null, new Color(0, 0, 0)));
		GridBagLayout gbl_panelCreateTraceFile = new GridBagLayout();
		gbl_panelCreateTraceFile.columnWidths = new int[] { 956, 0 };
		gbl_panelCreateTraceFile.rowHeights = new int[] { 0, 0, 0, 0, 0 };
		gbl_panelCreateTraceFile.columnWeights = new double[] { 1.0, Double.MIN_VALUE };
		gbl_panelCreateTraceFile.rowWeights = new double[] { 1.0, 0.0, 0.0, 1.0, Double.MIN_VALUE };
		setLayout(gbl_panelCreateTraceFile);

		GridBagConstraints gbc_panelHooks = new GridBagConstraints();
		gbc_panelHooks.insets = new Insets(0, 0, 5, 0);
		gbc_panelHooks.fill = GridBagConstraints.BOTH;
		gbc_panelHooks.gridx = 0;
		gbc_panelHooks.gridy = 0;
		setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Add hooks",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		add(panelHooks, gbc_panelHooks);
		GridBagLayout gbl_panelHooks = new GridBagLayout();
		gbl_panelHooks.columnWidths = new int[] { 80, 100, 200, 0, 0 };
		gbl_panelHooks.rowHeights = new int[] { 0, 50 };
		gbl_panelHooks.columnWeights = new double[] { 1.0, 1.0, 1.0, 0.0, 0.0 };
		gbl_panelHooks.rowWeights = new double[] { 1.0, 1.0 };
		panelHooks.setLayout(gbl_panelHooks);

		GridBagConstraints gbc_lblFunctionName = new GridBagConstraints();
		gbc_lblFunctionName.insets = new Insets(0, 0, 5, 5);
		gbc_lblFunctionName.gridx = 0;
		gbc_lblFunctionName.gridy = 0;
		panelHooks.add(lblFunctionName, gbc_lblFunctionName);

		GridBagConstraints gbc_lblFunctionNamed = new GridBagConstraints();
		gbc_lblFunctionNamed.insets = new Insets(0, 0, 5, 5);
		gbc_lblFunctionNamed.gridx = 1;
		gbc_lblFunctionNamed.gridy = 0;
		panelHooks.add(lblFunctionNamed, gbc_lblFunctionNamed);

		GridBagConstraints gbc_lblFunctionAddress = new GridBagConstraints();
		gbc_lblFunctionAddress.insets = new Insets(0, 0, 5, 5);
		gbc_lblFunctionAddress.gridx = 2;
		gbc_lblFunctionAddress.gridy = 0;
		panelHooks.add(lblFunctionAddress, gbc_lblFunctionAddress);

		GridBagConstraints gbc_lblMode = new GridBagConstraints();
		gbc_lblMode.insets = new Insets(0, 0, 5, 5);
		gbc_lblMode.gridx = 3;
		gbc_lblMode.gridy = 0;
		panelHooks.add(lblMode, gbc_lblMode);

		GridBagConstraints gbc_listFunctionName = new GridBagConstraints();
		gbc_listFunctionName.insets = new Insets(0, 0, 0, 5);
		gbc_listFunctionName.fill = GridBagConstraints.BOTH;
		gbc_listFunctionName.gridx = 0;
		gbc_listFunctionName.gridy = 1;
		listFunctionName.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		panelHooks.add(listFunctionName, gbc_listFunctionName);

		GridBagConstraints gbc_listBlockName = new GridBagConstraints();
		gbc_listBlockName.insets = new Insets(0, 0, 0, 5);
		gbc_listBlockName.fill = GridBagConstraints.BOTH;
		gbc_listBlockName.gridx = 1;
		gbc_listBlockName.gridy = 1;
		panelHooks.add(listBlockName, gbc_listBlockName);

		GridBagConstraints gbc_listFunctionAddress = new GridBagConstraints();
		gbc_listFunctionAddress.insets = new Insets(0, 0, 0, 5);
		gbc_listFunctionAddress.fill = GridBagConstraints.BOTH;
		gbc_listFunctionAddress.gridx = 2;
		gbc_listFunctionAddress.gridy = 1;
		panelHooks.add(listFunctionAddress, gbc_listFunctionAddress);

		GridBagConstraints gbc_comboBoxHookMode = new GridBagConstraints();
		gbc_comboBoxHookMode.insets = new Insets(0, 0, 0, 5);
		gbc_comboBoxHookMode.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBoxHookMode.gridx = 3;
		gbc_comboBoxHookMode.gridy = 1;
		comboBoxHookMode.setModel(new DefaultComboBoxModel<>(new String[] { "model", "skip", "taint" }));
		panelHooks.add(comboBoxHookMode, gbc_comboBoxHookMode);

		GridBagConstraints gbc_btnAddHook = new GridBagConstraints();
		gbc_btnAddHook.gridx = 4;
		gbc_btnAddHook.gridy = 1;
		panelHooks.add(btnAddHook, gbc_btnAddHook);

		JPanel panelRegisters = new JPanel();
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
		GridBagConstraints gbc_panelRegisters = new GridBagConstraints();
		gbc_panelRegisters.weighty = 1.0;
		gbc_panelRegisters.weightx = 1.0;
		gbc_panelRegisters.anchor = GridBagConstraints.NORTHWEST;
		gbc_panelRegisters.fill = GridBagConstraints.BOTH;
		gbc_panelRegisters.insets = new Insets(0, 0, 5, 0);
		gbc_panelRegisters.gridx = 0;
		gbc_panelRegisters.gridy = 1;
		add(panelRegisters, gbc_panelRegisters);

		JPanel panelMemory = new JPanel();
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
		GridBagConstraints gbc_panelMemory = new GridBagConstraints();
		gbc_panelMemory.weighty = 1.0;
		gbc_panelMemory.weightx = 1.0;
		gbc_panelMemory.anchor = GridBagConstraints.NORTHWEST;
		gbc_panelMemory.fill = GridBagConstraints.BOTH;
		gbc_panelMemory.insets = new Insets(0, 0, 5, 0);
		gbc_panelMemory.gridx = 0;
		gbc_panelMemory.gridy = 2;
		add(panelMemory, gbc_panelMemory);

		JPanel panelButtons = new JPanel();
		GridBagConstraints gbc_panelButtons = new GridBagConstraints();
		gbc_panelButtons.fill = GridBagConstraints.BOTH;
		gbc_panelButtons.gridx = 0;
		gbc_panelButtons.gridy = 3;
		add(panelButtons, gbc_panelButtons);

		panelButtons.add(btnLoadTraceFile);

		panelButtons.add(btnCreateTraceFile);

		panelButtons.add(btnClearTraceFile);
		
		setupComponents();
	}

	private void setupComponents() {
		setupBtnAddHook();
		textFieldRegisterValue.setDocument(new HexDocument());
		textFieldMemoryAddress.setDocument(new HexDocument());
		textFieldMemoryValue.setDocument(new HexDocument());

		setupBtnAddRegister();
		setupBtnRemoveRegister();
		scrollPaneRegisters.setViewportView(registerList);

		setupBtnAddMemory();
		setupBtnRemoveMemory();
		scrollPaneMemory.setViewportView(memoryList);

		setupBtnLoadTraceFile();
		setupBtnCreateTraceFile();
		setupBtnClearTraceFile();

		plugin.addProgramOpenendListener(this::setupHookLists);
	}

	private void setupHookLists(Program p) {
		functionHelper = new FunctionHelper(p);
		DefaultListModel<String> functionNameModel = new DefaultListModel<>();
		List<String> functionNames = functionHelper
				.getFunctionNames()
				.stream()
				.sorted()
				.collect(Collectors.toList());
		functionNameModel.addAll(functionNames);
		listFunctionName.setModel(functionNameModel);
		listFunctionName.addListSelectionListener((ListSelectionEvent e) -> {
			List<String> blockNames = functionHelper
					.getBlockNames(listFunctionName.getSelectedValuesList())
					.stream()
					.sorted()
					.collect(Collectors.toList());
			DefaultListModel<String> blockNameModel = new DefaultListModel<>();
			blockNameModel.addAll(blockNames);
			listBlockName.setModel(blockNameModel);
			listBlockName.addListSelectionListener((ListSelectionEvent e2) -> {
				List<Address> addresses = functionHelper
						.getAddresses(listFunctionName.getSelectedValuesList(),
								listBlockName.getSelectedValuesList())
						.stream()
						.sorted()
						.collect(Collectors.toList());
				DefaultListModel<Address> addressesModel = new DefaultListModel<>();
				addressesModel.addAll(addresses);
				listFunctionAddress.setModel(addressesModel);
				listFunctionAddress.setSelectedIndices(IntStream.range(0, addresses.size()).toArray());
			});
			listBlockName.setSelectedIndices(IntStream.range(0, blockNames.size()).toArray());
		});
	}

	private void setupBtnAddHook() {
		btnAddHook.addActionListener(e -> {
			String libraryName = "libc";
			String functionName = listFunctionName.getSelectedValue();
			for (Address a : listFunctionAddress.getSelectedValuesList()) {
				String entryAddress = "0x" + a.toString();
				String leaveAddress = "0x" + a.next().toString();
				String mode = (String) comboBoxHookMode.getSelectedItem();

				traceFileController.addHook(libraryName, functionName, entryAddress, leaveAddress, mode);
			}
		});
	}

	private void setupBtnAddRegister() {
		btnAddRegister.addActionListener(e -> {
			String name = textFieldRegisterName.getText();
			String value = textFieldRegisterValue.getText();
			boolean isSymbolic = chckbxIsRegisterSymbolic.isSelected();

			for (int i = 0; i < registerListModel.getSize(); i++) {
				List<String> register = registerListModel.getElementAt(i);
				if (register.get(0).equals(name)) {
					Msg.showError(this, this, "Register duplicate", "Register " + name + " already exists");
					return;
				}
			}

			List<String> register = new ArrayList<>(Arrays.asList(name, value));
			if (isSymbolic) {
				register.add(traceFileController.getSymbolicMarker());
			}
			registerListModel.addElement(register);

			traceFileController.addEntryStateRegister(name, value, isSymbolic);
		});
	}

	private void setupBtnRemoveRegister() {
		btnRemoveRegister.addActionListener(e -> {
			// Remove registers from trace file data structure
			List<List<String>> selectedItems = registerList.getSelectedValuesList();
			Set<String> registerNames = new HashSet<>();
			for (List<String> item : selectedItems) {
				registerNames.add(item.get(0));
			}
			for (String name : registerNames) {
				traceFileController.removeEntryStateRegister(name);
			}

			// Remove registers from UI
			int[] selectedIndices = registerList.getSelectedIndices();
			for (int i = selectedIndices.length - 1; i >= 0; i--) {
				registerListModel.remove(selectedIndices[i]);
			}
		});
	}

	private void setupBtnAddMemory() {
		btnAddMemory.addActionListener(e -> {
			String address = textFieldMemoryAddress.getText();
			String value = textFieldMemoryValue.getText();
			boolean isSymbolic = chckbxIsMemorySymbolic.isSelected();

			for (int i = 0; i < memoryListModel.getSize(); i++) {
				List<String> memory = memoryListModel.getElementAt(i);
				if (memory.get(0).equals(address)) {
					Msg.showError(this, this, "Memory address duplicate",
							"Memory address " + address + " already exists");
					return;
				}
			}

			List<String> memoryUnit = new ArrayList<>(Arrays.asList(address, value));
			if (isSymbolic) {
				memoryUnit.add(traceFileController.getSymbolicMarker());
			}
			memoryListModel.addElement(memoryUnit);

			traceFileController.addEntryStateMemory(address, value, isSymbolic);
		});
	}

	private void setupBtnRemoveMemory() {
		btnRemoveMemory.addActionListener(e -> {
			// Remove memory addresses from trace file data structure
			List<List<String>> selectedItems = memoryList.getSelectedValuesList();
			Set<String> memoryAddresses = new HashSet<>();
			for (List<String> item : selectedItems) {
				memoryAddresses.add(item.get(0));
			}
			for (String address : memoryAddresses) {
				traceFileController.removeEntryStateMemory(address);
			}

			// Remove memory addresses from UI
			int[] selectedIndices = memoryList.getSelectedIndices();
			for (int i = selectedIndices.length - 1; i >= 0; i--) {
				memoryListModel.remove(selectedIndices[i]);
			}
		});
	}

	private void setupBtnLoadTraceFile() {
		btnLoadTraceFile.addActionListener(e -> {
			clearTraceFile();
		});
	}

	private void setupBtnCreateTraceFile() {
		btnCreateTraceFile.addActionListener(e -> {
			traceFileController.createTraceFile(this);
		});
	}

	private void setupBtnClearTraceFile() {
		btnClearTraceFile.addActionListener(e -> {
			clearTraceFile();
		});
	}

	private void clearTraceFile() {
		// Clear registers
		textFieldRegisterName.setText("");
		textFieldRegisterValue.setDocument(new HexDocument());
		chckbxIsRegisterSymbolic.setSelected(false);
		registerListModel.clear();

		// Clear memory
		textFieldMemoryAddress.setDocument(new HexDocument());
		textFieldMemoryValue.setDocument(new HexDocument());
		chckbxIsMemorySymbolic.setSelected(false);
		memoryListModel.clear();

		// Clear data structure
		traceFileController.clearTraceFile();
	}
}
