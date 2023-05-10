package view;

import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.yaml.snakeyaml.Yaml;

import ctrl.TraceFileController;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ghidrion.GhidrionPlugin;
import model.Hook;
import model.Hook.Mode;
import model.MemoryEntry;
import model.MorionTraceFile;

import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.DefaultListModel;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JScrollPane;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JTabbedPane;

public class CreateTraceFilePanel extends JPanel {
	private final GhidrionPlugin plugin;
	private final MorionTraceFile traceFile;
	private final HookPanel panelHooks;

	private final JTextField textFieldRegisterName = new JTextField();
	private final JTextField textFieldRegisterValue = new JTextField();
	private final JCheckBox chckbxIsRegisterSymbolic = new JCheckBox("");
	private final JButton btnAddRegister = new JButton("Add");
	private final JButton btnRemoveRegister = new JButton("Remove");
	private final JScrollPane scrollPaneRegisters = new JScrollPane();
	private final JTextField textFieldMemoryAddress = new JTextField();
	private final JTextField textFieldMemoryValue = new JTextField();
	private final JCheckBox chckbxIsMemorySymbolic = new JCheckBox("");
	private final JButton btnAddMemory = new JButton("Add");
	private final JButton btnRemoveMemory = new JButton("Remove");
	private final JScrollPane scrollPaneMemory = new JScrollPane();
	private final JButton btnLoadTraceFile = new JButton("Load");
	private final JButton btnCreateTraceFile = new JButton("Save As");
	private final JButton btnClearTraceFile = new JButton("Clear");
	private final JList<MemoryEntry> registerList = new JList<>();
	private final JList<MemoryEntry> memoryList = new JList<>();
	private final JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
	private final JPanel panelData = new JPanel();

	public CreateTraceFilePanel(GhidrionPlugin plugin, MorionTraceFile traceFile) {
		this.plugin = plugin;
		this.traceFile = traceFile;
		this.panelHooks = new HookPanel(plugin, traceFile);

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
		add(panelButtons, gbc_panelButtons);

		panelButtons.add(btnLoadTraceFile);

		panelButtons.add(btnCreateTraceFile);

		panelButtons.add(btnClearTraceFile);

		GridBagConstraints gbc_tabbedPane = new GridBagConstraints();
		gbc_tabbedPane.insets = new Insets(0, 0, 5, 0);
		gbc_tabbedPane.fill = GridBagConstraints.BOTH;
		gbc_tabbedPane.gridx = 0;
		gbc_tabbedPane.gridy = 0;
		add(tabbedPane, gbc_tabbedPane);
		tabbedPane.addTab("Hooks", null, panelHooks, null);
		GridBagLayout gbl_panelData = new GridBagLayout();
		gbl_panelData.columnWidths = new int[] { 522 };
		gbl_panelData.rowHeights = new int[] { 211, 211, 0 };
		gbl_panelData.columnWeights = new double[] { 0.0 };
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

		textFieldMemoryAddress.setText("0x");
		GridBagConstraints gbc_textFieldMemoryAddress = new GridBagConstraints();
		gbc_textFieldMemoryAddress.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldMemoryAddress.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldMemoryAddress.gridx = 0;
		gbc_textFieldMemoryAddress.gridy = 1;
		panelMemory.add(textFieldMemoryAddress, gbc_textFieldMemoryAddress);
		textFieldMemoryAddress.setColumns(10);

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

		GridBagConstraints gbc_textFieldRegisterName = new GridBagConstraints();
		gbc_textFieldRegisterName.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldRegisterName.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldRegisterName.gridx = 0;
		gbc_textFieldRegisterName.gridy = 1;
		panelRegisters.add(textFieldRegisterName, gbc_textFieldRegisterName);
		textFieldRegisterName.setColumns(10);

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
		traceFile.getEntryRegisters().addObserver(newList -> {
			DefaultListModel<MemoryEntry> listModel = new DefaultListModel<>();
			listModel.addAll(newList.stream().sorted().collect(Collectors.toList()));
			registerList.setModel(listModel);
		});
	}

	private void setupBtnAddRegister() {
		btnAddRegister.addActionListener(e -> {
			String name = textFieldRegisterName.getText();
			String value = textFieldRegisterValue.getText();
			boolean isSymbolic = chckbxIsRegisterSymbolic.isSelected();
			traceFile.getEntryRegisters().add(new MemoryEntry(name, value, isSymbolic));
		});
	}

	private void setupBtnRemoveRegister() {
		btnRemoveRegister.addActionListener(e -> {
			traceFile.getEntryRegisters().removeAll(registerList.getSelectedValuesList());
			registerList.setSelectedIndex(0);
		});
	}

	private void setupListMemory() {
		traceFile.getEntryMemory().addObserver(newList -> {
			DefaultListModel<MemoryEntry> listModel = new DefaultListModel<>();
			listModel.addAll(newList.stream().sorted().collect(Collectors.toList()));
			memoryList.setModel(listModel);
		});
	}

	private void setupBtnAddMemory() {
		btnAddMemory.addActionListener(e -> {
			String address = textFieldMemoryAddress.getText();
			String value = textFieldMemoryValue.getText();
			boolean isSymbolic = chckbxIsMemorySymbolic.isSelected();
			traceFile.getEntryMemory().add(new MemoryEntry(address, value, isSymbolic));
		});
	}

	private void setupBtnRemoveMemory() {
		btnRemoveMemory.addActionListener(e -> {
			traceFile.getEntryMemory().removeAll(memoryList.getSelectedValuesList());
			memoryList.setSelectedIndex(0);
		});
	}

	private void setupBtnLoadTraceFile() {
		btnLoadTraceFile.addActionListener(e -> {
			// Warn user that current trace file gets cleared
			String warning = "Are you sure you want to proceed? The current editor entries are cleared.";
			int warningResult = JOptionPane.showConfirmDialog(this, warning, "Confirmation", JOptionPane.OK_CANCEL_OPTION);
			if (warningResult != JOptionPane.OK_OPTION) {
				return;
			}
			
			clearTraceFile();
			JFileChooser fileChooser = new JFileChooser();
			FileNameExtensionFilter filter = new FileNameExtensionFilter("YAML files", "yaml");
			fileChooser.setFileFilter(filter);
			int chooseResult = fileChooser.showOpenDialog(this);
			if (chooseResult != JFileChooser.APPROVE_OPTION) {
				return;
			}
			File selectedTraceFile = fileChooser.getSelectedFile();
			InputStream input;
			try {
				input = new FileInputStream(selectedTraceFile);
			} catch (FileNotFoundException ex) {
				Msg.showError(this, this, "No trace file", "Couldn't find trace file");
				ex.printStackTrace();
				return;
			}

			Map<String, Object> newTraceFile = new Yaml().load(input);

			// Load hooks
			Map<String, Map<String, List<Map<String, String>>>> hookMap = (Map<String, Map<String, List<Map<String, String>>>>) newTraceFile.get(TraceFileController.HOOKS);
			traceFile.getHooks().addAll(buildHooks(hookMap));
			
			// Load states
			Map<String, Map<String, Map<String, List<String>>>> stateMap = (Map<String, Map<String, Map<String, List<String>>>>) newTraceFile.get(TraceFileController.STATES);
			Map<String, Map<String, List<String>>> entryStates = stateMap.get(TraceFileController.ENTRY_STATE);

			// Load registers
			Map<String, List<String>> entryRegMap = entryStates.get(TraceFileController.STATE_REGISTERS);
			traceFile.getEntryRegisters().addAll(buildMemoryEntries(entryRegMap));
			Map<String, List<String>> entryMemMap = entryStates.get(TraceFileController.STATE_MEMORY);
			traceFile.getEntryMemory().addAll(buildMemoryEntries(entryMemMap));
		});
	}
	
	private List<Hook> buildHooks(Map<String, Map<String, List<Map<String, String>>>> hookMap) {
		List<Hook> hooks = new ArrayList<>();
		Map<String, List<Map<String, String>>> functions = hookMap.get("libc"); // Libc is hardcoded for now
		for (String functionName : functions.keySet()) {
			for (Map<String, String> hookDetails : functions.get(functionName)) {
				String entry = hookDetails.get(TraceFileController.HOOK_ENTRY);
				Address entryAddress = plugin.getCurrentProgram().getAddressFactory().getAddress(entry);
				Mode mode = Mode.fromValue(hookDetails.get(TraceFileController.HOOK_MODE));
				hooks.add(new Hook(functionName, entryAddress, mode));
			}
		}
		return hooks;
	}
	
	private List<MemoryEntry> buildMemoryEntries(Map<String, List<String>> entryMap) {
		List<MemoryEntry> entries = new ArrayList<>();
		for (String name : entryMap.keySet()) {
			String value = entryMap.get(name).get(0);
			boolean symbolic = (entryMap.get(name).size() > 1);
			entries.add(new MemoryEntry(name, value, symbolic));
		}
		return entries;
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
