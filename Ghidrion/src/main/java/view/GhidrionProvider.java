package view;

import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.TitledBorder;

import ctrl.TraceFileController;
import docking.ComponentProvider;
import ghidrion.GhidrionPlugin;

import javax.swing.border.EtchedBorder;
import java.awt.Color;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JTextField;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListModel;
import javax.swing.JCheckBox;
import javax.swing.JColorChooser;
import javax.swing.LayoutStyle.ComponentPlacement;

public class GhidrionProvider extends ComponentProvider {
	private GhidrionPlugin plugin;
	
	private TraceFileController traceFileController = new TraceFileController();

    private DefaultListModel<Map<Long,List<String>>> hookListModel = new DefaultListModel<>();
	private JList<Map<Long, List<String>>> hookList = new JList<>(hookListModel);
    private DefaultListModel<List<String>> registerListModel = new DefaultListModel<>();
	private JList<List<String>> registerList = new JList<>(registerListModel);
    private DefaultListModel<List<String>> memoryListModel = new DefaultListModel<>();
	private JList<List<String>> memoryList = new JList<>(memoryListModel);
	private DefaultListModel<String> traceListModel = new DefaultListModel<>();
	private JList<String> traceList = new JList<>(traceListModel);
	
	private JPanel panel;
	private JTextField textFieldLibrary;
	private JTextField textFieldFunction;
	private JTextField textFieldEntry;
	private JTextField textFieldLeave;
	private JTextField textFieldTarget;
	private JTextField textFieldRegisterName;
	private JTextField textFieldRegisterValue;
	private JTextField textFieldMemoryAddress;
	private JTextField textFieldMemoryValue;

	private Color traceColor = Color.CYAN;

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner) {
		super(plugin.getTool(), pluginName, owner);
		this.plugin = plugin;

		buildPanel();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel();
		setVisible(true);

		/*
		 * ----------------------------------------------------------------------------------------------------------
		 * WHEN UPDATING THE GhidrionUI, REPLACE FROME HERE.
		 * ALSO, REPLACE frame.getContentPane() WITH panel AFTER PASTING THE NEW GhdrionUI
		 * ----------------------------------------------------------------------------------------------------------
		 */
		JPanel panelCreateTraceFile = new JPanel();
		panelCreateTraceFile.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Create init trace file", TitledBorder.LEADING, TitledBorder.ABOVE_TOP, null, new Color(0, 0, 0)));
		
		JPanel panelDisplayTraceFile = new JPanel();
		panelDisplayTraceFile.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Display Morion trace file", TitledBorder.LEADING, TitledBorder.ABOVE_TOP, null, new Color(0, 0, 0)));
		GroupLayout groupLayout = new GroupLayout(panel);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.TRAILING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING)
						.addComponent(panelCreateTraceFile, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 968, Short.MAX_VALUE)
						.addComponent(panelDisplayTraceFile, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 968, Short.MAX_VALUE))
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(Alignment.TRAILING, groupLayout.createSequentialGroup()
					.addContainerGap()
					.addComponent(panelCreateTraceFile, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED, 54, Short.MAX_VALUE)
					.addComponent(panelDisplayTraceFile, GroupLayout.PREFERRED_SIZE, 195, GroupLayout.PREFERRED_SIZE)
					.addContainerGap())
		);
		GridBagLayout gbl_panelDisplayTraceFile = new GridBagLayout();
		gbl_panelDisplayTraceFile.columnWidths = new int[]{0, 0, 0, 0};
		gbl_panelDisplayTraceFile.rowHeights = new int[]{0, 0, 0, 0};
		gbl_panelDisplayTraceFile.columnWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_panelDisplayTraceFile.rowWeights = new double[]{0.0, 1.0, 0.0, Double.MIN_VALUE};
		panelDisplayTraceFile.setLayout(gbl_panelDisplayTraceFile);
		
		JButton btnDisplayTrace = new JButton("Import and Display");
		GridBagConstraints gbc_btnDisplayTrace = new GridBagConstraints();
		gbc_btnDisplayTrace.insets = new Insets(0, 0, 5, 5);
		gbc_btnDisplayTrace.gridx = 0;
		gbc_btnDisplayTrace.gridy = 0;
		panelDisplayTraceFile.add(btnDisplayTrace, gbc_btnDisplayTrace);
		
		JButton btnChooseTraceColor = new JButton("Color");
		GridBagConstraints gbc_btnChooseTraceColor = new GridBagConstraints();
		gbc_btnChooseTraceColor.insets = new Insets(0, 0, 5, 5);
		gbc_btnChooseTraceColor.gridx = 1;
		gbc_btnChooseTraceColor.gridy = 0;
		panelDisplayTraceFile.add(btnChooseTraceColor, gbc_btnChooseTraceColor);
		
		JScrollPane scrollPaneTraces = new JScrollPane();
		GridBagConstraints gbc_scrollPaneTraces = new GridBagConstraints();
		gbc_scrollPaneTraces.insets = new Insets(0, 0, 5, 0);
		gbc_scrollPaneTraces.gridwidth = 3;
		gbc_scrollPaneTraces.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneTraces.gridx = 0;
		gbc_scrollPaneTraces.gridy = 1;
		panelDisplayTraceFile.add(scrollPaneTraces, gbc_scrollPaneTraces);
		
		JButton btnRemoveTraces = new JButton("Remove selected traces");
		GridBagConstraints gbc_btnRemoveTraces = new GridBagConstraints();
		gbc_btnRemoveTraces.insets = new Insets(0, 0, 0, 5);
		gbc_btnRemoveTraces.gridx = 0;
		gbc_btnRemoveTraces.gridy = 2;
		panelDisplayTraceFile.add(btnRemoveTraces, gbc_btnRemoveTraces);
		GridBagLayout gbl_panelCreateTraceFile = new GridBagLayout();
		gbl_panelCreateTraceFile.columnWidths = new int[]{956, 0};
		gbl_panelCreateTraceFile.rowHeights = new int[]{144, 144, 144, 23, 0};
		gbl_panelCreateTraceFile.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_panelCreateTraceFile.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panelCreateTraceFile.setLayout(gbl_panelCreateTraceFile);
		
		JPanel panelHooks = new JPanel();
		panelHooks.setBorder(new TitledBorder(null, "Add hook", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagLayout gbl_panelHooks = new GridBagLayout();
		gbl_panelHooks.columnWidths = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panelHooks.rowHeights = new int[]{0, 0, 75, 0};
		gbl_panelHooks.columnWeights = new double[]{1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.0, Double.MIN_VALUE};
		gbl_panelHooks.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
		panelHooks.setLayout(gbl_panelHooks);
		
		JLabel lblLibrary = new JLabel("Library name");
		GridBagConstraints gbc_lblLibrary = new GridBagConstraints();
		gbc_lblLibrary.insets = new Insets(0, 0, 5, 5);
		gbc_lblLibrary.gridx = 0;
		gbc_lblLibrary.gridy = 0;
		panelHooks.add(lblLibrary, gbc_lblLibrary);
		
		JLabel lblFunction = new JLabel("Function name");
		GridBagConstraints gbc_lblFunction = new GridBagConstraints();
		gbc_lblFunction.insets = new Insets(0, 0, 5, 5);
		gbc_lblFunction.gridx = 1;
		gbc_lblFunction.gridy = 0;
		panelHooks.add(lblFunction, gbc_lblFunction);
		
		JLabel lblEntry = new JLabel("Entry address");
		GridBagConstraints gbc_lblEntry = new GridBagConstraints();
		gbc_lblEntry.insets = new Insets(0, 0, 5, 5);
		gbc_lblEntry.gridx = 2;
		gbc_lblEntry.gridy = 0;
		panelHooks.add(lblEntry, gbc_lblEntry);
		
		JLabel lblLeave = new JLabel("Leave address");
		GridBagConstraints gbc_lblLeave = new GridBagConstraints();
		gbc_lblLeave.insets = new Insets(0, 0, 5, 5);
		gbc_lblLeave.gridx = 3;
		gbc_lblLeave.gridy = 0;
		panelHooks.add(lblLeave, gbc_lblLeave);
		
		JLabel lblTarget = new JLabel("Target address");
		GridBagConstraints gbc_lblTarget = new GridBagConstraints();
		gbc_lblTarget.insets = new Insets(0, 0, 5, 5);
		gbc_lblTarget.gridx = 4;
		gbc_lblTarget.gridy = 0;
		panelHooks.add(lblTarget, gbc_lblTarget);
		
		JLabel lblMode = new JLabel("Mode");
		GridBagConstraints gbc_lblMode = new GridBagConstraints();
		gbc_lblMode.insets = new Insets(0, 0, 5, 5);
		gbc_lblMode.gridx = 5;
		gbc_lblMode.gridy = 0;
		panelHooks.add(lblMode, gbc_lblMode);
		
		textFieldLibrary = new JTextField();
		GridBagConstraints gbc_textFieldLibrary = new GridBagConstraints();
		gbc_textFieldLibrary.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldLibrary.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldLibrary.gridx = 0;
		gbc_textFieldLibrary.gridy = 1;
		panelHooks.add(textFieldLibrary, gbc_textFieldLibrary);
		textFieldLibrary.setColumns(10);
		
		textFieldFunction = new JTextField();
		GridBagConstraints gbc_textFieldFunction = new GridBagConstraints();
		gbc_textFieldFunction.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldFunction.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldFunction.gridx = 1;
		gbc_textFieldFunction.gridy = 1;
		panelHooks.add(textFieldFunction, gbc_textFieldFunction);
		textFieldFunction.setColumns(10);
		
		textFieldEntry = new JTextField();
		textFieldEntry.setText("0x");
		GridBagConstraints gbc_textFieldEntry = new GridBagConstraints();
		gbc_textFieldEntry.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldEntry.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldEntry.gridx = 2;
		gbc_textFieldEntry.gridy = 1;
		panelHooks.add(textFieldEntry, gbc_textFieldEntry);
		textFieldEntry.setColumns(10);
		
		textFieldLeave = new JTextField();
		textFieldLeave.setText("0x");
		GridBagConstraints gbc_textFieldLeave = new GridBagConstraints();
		gbc_textFieldLeave.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldLeave.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldLeave.gridx = 3;
		gbc_textFieldLeave.gridy = 1;
		panelHooks.add(textFieldLeave, gbc_textFieldLeave);
		textFieldLeave.setColumns(10);
		
		textFieldTarget = new JTextField();
		textFieldTarget.setText("0x");
		GridBagConstraints gbc_textFieldTarget = new GridBagConstraints();
		gbc_textFieldTarget.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldTarget.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldTarget.gridx = 4;
		gbc_textFieldTarget.gridy = 1;
		panelHooks.add(textFieldTarget, gbc_textFieldTarget);
		textFieldTarget.setColumns(10);
		
		JComboBox comboBoxHookMode = new JComboBox();
		comboBoxHookMode.setModel(new DefaultComboBoxModel(new String[] {"model", "skip", "taint"}));
		GridBagConstraints gbc_comboBoxHookMode = new GridBagConstraints();
		gbc_comboBoxHookMode.insets = new Insets(0, 0, 5, 5);
		gbc_comboBoxHookMode.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBoxHookMode.gridx = 5;
		gbc_comboBoxHookMode.gridy = 1;
		panelHooks.add(comboBoxHookMode, gbc_comboBoxHookMode);
		
		JButton btnAddHook = new JButton("Add");
		GridBagConstraints gbc_btnAddHook = new GridBagConstraints();
		gbc_btnAddHook.insets = new Insets(0, 0, 5, 5);
		gbc_btnAddHook.gridx = 6;
		gbc_btnAddHook.gridy = 1;
		panelHooks.add(btnAddHook, gbc_btnAddHook);
		
		JButton btnRemoveHook = new JButton("Remove");
		GridBagConstraints gbc_btnRemoveHook = new GridBagConstraints();
		gbc_btnRemoveHook.insets = new Insets(0, 0, 5, 0);
		gbc_btnRemoveHook.gridx = 7;
		gbc_btnRemoveHook.gridy = 1;
		panelHooks.add(btnRemoveHook, gbc_btnRemoveHook);
		
		JScrollPane scrollPaneHooks = new JScrollPane();
		GridBagConstraints gbc_scrollPaneHooks = new GridBagConstraints();
		gbc_scrollPaneHooks.gridwidth = 8;
		gbc_scrollPaneHooks.insets = new Insets(0, 0, 0, 5);
		gbc_scrollPaneHooks.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneHooks.gridx = 0;
		gbc_scrollPaneHooks.gridy = 2;
		panelHooks.add(scrollPaneHooks, gbc_scrollPaneHooks);
		GridBagConstraints gbc_panelHooks = new GridBagConstraints();
		gbc_panelHooks.weighty = 1.0;
		gbc_panelHooks.weightx = 1.0;
		gbc_panelHooks.anchor = GridBagConstraints.NORTHWEST;
		gbc_panelHooks.fill = GridBagConstraints.BOTH;
		gbc_panelHooks.insets = new Insets(0, 0, 5, 0);
		gbc_panelHooks.gridx = 0;
		gbc_panelHooks.gridy = 0;
		panelCreateTraceFile.add(panelHooks, gbc_panelHooks);
		
		JPanel panelRegisters = new JPanel();
		panelRegisters.setBorder(new TitledBorder(null, "Add register", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagLayout gbl_panelRegisters = new GridBagLayout();
		gbl_panelRegisters.columnWidths = new int[]{0, 0, 0, 0, 0, 0};
		gbl_panelRegisters.rowHeights = new int[]{0, 0, 75, 0};
		gbl_panelRegisters.columnWeights = new double[]{1.0, 1.0, 1.0, 0.0, 0.0, Double.MIN_VALUE};
		gbl_panelRegisters.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
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
		
		JCheckBox chckbxIsRegisterSymbolic = new JCheckBox("");
		GridBagConstraints gbc_chckbxIsRegisterSymbolic = new GridBagConstraints();
		gbc_chckbxIsRegisterSymbolic.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxIsRegisterSymbolic.gridx = 2;
		gbc_chckbxIsRegisterSymbolic.gridy = 1;
		panelRegisters.add(chckbxIsRegisterSymbolic, gbc_chckbxIsRegisterSymbolic);
		
		JButton btnAddRegister = new JButton("Add");
		GridBagConstraints gbc_btnAddRegister = new GridBagConstraints();
		gbc_btnAddRegister.insets = new Insets(0, 0, 5, 5);
		gbc_btnAddRegister.gridx = 3;
		gbc_btnAddRegister.gridy = 1;
		panelRegisters.add(btnAddRegister, gbc_btnAddRegister);
		
		JButton btnRemoveRegister = new JButton("Remove");
		GridBagConstraints gbc_btnRemoveRegister = new GridBagConstraints();
		gbc_btnRemoveRegister.insets = new Insets(0, 0, 5, 0);
		gbc_btnRemoveRegister.gridx = 4;
		gbc_btnRemoveRegister.gridy = 1;
		panelRegisters.add(btnRemoveRegister, gbc_btnRemoveRegister);
		
		JScrollPane scrollPaneRegisters = new JScrollPane();
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
		panelCreateTraceFile.add(panelRegisters, gbc_panelRegisters);
		
		JPanel panelMemory = new JPanel();
		panelMemory.setBorder(new TitledBorder(null, "Add memory", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagLayout gbl_panelMemory = new GridBagLayout();
		gbl_panelMemory.columnWidths = new int[]{0, 0, 0, 0, 0, 0};
		gbl_panelMemory.rowHeights = new int[]{0, 0, 75, 0};
		gbl_panelMemory.columnWeights = new double[]{1.0, 1.0, 1.0, 0.0, 0.0, Double.MIN_VALUE};
		gbl_panelMemory.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
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
		
		JCheckBox chckbxIsMemorySymbolic = new JCheckBox("");
		GridBagConstraints gbc_chckbxIsMemorySymbolic = new GridBagConstraints();
		gbc_chckbxIsMemorySymbolic.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxIsMemorySymbolic.gridx = 2;
		gbc_chckbxIsMemorySymbolic.gridy = 1;
		panelMemory.add(chckbxIsMemorySymbolic, gbc_chckbxIsMemorySymbolic);
		
		JButton btnAddMemory = new JButton("Add");
		GridBagConstraints gbc_btnAddMemory = new GridBagConstraints();
		gbc_btnAddMemory.insets = new Insets(0, 0, 5, 5);
		gbc_btnAddMemory.gridx = 3;
		gbc_btnAddMemory.gridy = 1;
		panelMemory.add(btnAddMemory, gbc_btnAddMemory);
		
		JButton btnRemoveMemory = new JButton("Remove");
		GridBagConstraints gbc_btnRemoveMemory = new GridBagConstraints();
		gbc_btnRemoveMemory.insets = new Insets(0, 0, 5, 0);
		gbc_btnRemoveMemory.gridx = 4;
		gbc_btnRemoveMemory.gridy = 1;
		panelMemory.add(btnRemoveMemory, gbc_btnRemoveMemory);
		
		JScrollPane scrollPaneMemory = new JScrollPane();
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
		panelCreateTraceFile.add(panelMemory, gbc_panelMemory);
		
		JButton btnCreateInitTraceFile = new JButton("Create");
		GridBagConstraints gbc_btnCreateInitTraceFile = new GridBagConstraints();
		gbc_btnCreateInitTraceFile.anchor = GridBagConstraints.NORTH;
		gbc_btnCreateInitTraceFile.gridx = 0;
		gbc_btnCreateInitTraceFile.gridy = 3;
		panelCreateTraceFile.add(btnCreateInitTraceFile, gbc_btnCreateInitTraceFile);
		/*
		 * ----------------------------------------------------------------------------------------------------------
		 * WHEN UPDATING THE UI, REPLACE UNTIL HERE
		 * ----------------------------------------------------------------------------------------------------------
		 */
		
		textFieldEntry.setDocument(new HexDocument());
		textFieldLeave.setDocument(new HexDocument());
		textFieldTarget.setDocument(new HexDocument());
		textFieldRegisterValue.setDocument(new HexDocument());
		textFieldMemoryAddress.setDocument(new HexDocument());
		textFieldMemoryValue.setDocument(new HexDocument());
		
		setupBtnAddHook(btnAddHook, comboBoxHookMode);
		setupBtnRemoveHook(btnRemoveHook);
		scrollPaneHooks.setViewportView(hookList);
		
		setupBtnAddRegister(btnAddRegister, chckbxIsRegisterSymbolic);
		setupBtnRemoveRegister(btnRemoveRegister);
		scrollPaneRegisters.setViewportView(registerList);
		
		setupBtnAddMemory(btnAddMemory, chckbxIsMemorySymbolic);
		setupBtnRemoveMemory(btnRemoveMemory);
		scrollPaneMemory.setViewportView(memoryList);
		
		setupBtnCreateInitTraceFile(btnCreateInitTraceFile);
		
		setupBtnDisplayTrace(btnDisplayTrace);
		scrollPaneTraces.setViewportView(traceList);
		setupBtnChooseTraceColor(btnChooseTraceColor);
		setupBtnRemoveTraces(btnRemoveTraces);

		panel.setLayout(groupLayout);
	}

	private void setupBtnRemoveTraces(JButton btnRemoveTraces) {
		btnRemoveTraces.addActionListener(e -> {
			List<String> selectedItems = traceList.getSelectedValuesList();
			plugin.colorizerScript.decolorize(selectedItems);
			
			int[] selectedIndices = traceList.getSelectedIndices();
			for (int i = selectedIndices.length-1; i >= 0; i--) {
				traceListModel.remove(selectedIndices[i]);
			}
		});
	}

	private void setupBtnDisplayTrace(JButton btnDisplayTrace) {
		btnDisplayTrace.addActionListener(e -> {
			String traceName = plugin.colorizerScript.colorize(traceColor);
			if (traceName != null) {
				traceListModel.addElement(traceName);
			}
		});
	}

	private void setupBtnChooseTraceColor(JButton btnChooseTraceColor) {
		btnChooseTraceColor.setOpaque(true);
		btnChooseTraceColor.setBackground(traceColor);
		btnChooseTraceColor.addActionListener(e -> {
			Color newColor = JColorChooser.showDialog(panel, "Choose a color", traceColor);
			if (newColor != null) {
				traceColor = newColor;
				btnChooseTraceColor.setBackground(traceColor);
			}
		});
	}

	private void setupBtnAddHook(JButton btnAddHook, JComboBox<String> comboBoxHookMode) {
		btnAddHook.addActionListener(e -> {
            String libraryName = textFieldLibrary.getText();
            String functionName = textFieldFunction.getText();
            String entryAddress = textFieldEntry.getText();
            String leaveAddress = textFieldLeave.getText();
            String targetAddress = textFieldTarget.getText();
            String mode = (String) comboBoxHookMode.getSelectedItem();

            Map<Long, List<String>> hook = new HashMap<>();
            List<String> hookDetails = new ArrayList<>(
            		Arrays.asList(libraryName, functionName, entryAddress, leaveAddress, targetAddress, mode)
            	);
            long hookId = TraceFileController.generateHookId();
            hook.put(hookId, hookDetails);
            hookListModel.addElement(hook);
            
            traceFileController.addHook(libraryName, functionName, hookId, entryAddress, leaveAddress, targetAddress, mode);
		});
	}
	
	private void setupBtnRemoveHook(JButton btnRemoveHook) {
		btnRemoveHook.addActionListener(e -> {
			// Remove hook from trace file data structure
			List<Map<Long, List<String>>> selectedItems = hookList.getSelectedValuesList();
			Set<Long> hookIds = new HashSet<>();
			for (Map<Long, List<String>> item : selectedItems) {
				hookIds.addAll(item.keySet());
			}
			for (long hookId : hookIds) {
				traceFileController.removeHook(hookId);
			}
			
			// Remove hook from UI
			int[] selectedIndices = hookList.getSelectedIndices();
			for (int i = selectedIndices.length-1; i >= 0; i--) {
				hookListModel.remove(selectedIndices[i]);
			}
		});
	}

	private void setupBtnAddRegister(JButton btnAddRegister, JCheckBox cbIsSymbolic) {
		btnAddRegister.addActionListener(e -> {
        	String name = textFieldRegisterName.getText();
        	String value = textFieldRegisterValue.getText();
        	boolean isSymbolic = cbIsSymbolic.isSelected();

            List<String> register = new ArrayList<>(
            		Arrays.asList(name, value)
            	);
            if (isSymbolic) {
            	register.add(traceFileController.getSymbolicMarker());
            }
            registerListModel.addElement(register);
            
            traceFileController.addEntryStateRegister(name, value, isSymbolic);
		});
	}
	
	private void setupBtnRemoveRegister(JButton btnRemoveRegister) {
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
			for (int i = selectedIndices.length-1; i >= 0; i--) {
				registerListModel.remove(selectedIndices[i]);
			}
		});
	}

	private void setupBtnAddMemory(JButton btnAddMemory, JCheckBox chckbxIsMemorySymbolic) {
		btnAddMemory.addActionListener(e -> {
        	String address = textFieldMemoryAddress.getText();
        	String value = textFieldMemoryValue.getText();
        	boolean isSymbolic = chckbxIsMemorySymbolic.isSelected();

            List<String> memoryUnit = new ArrayList<>(
            		Arrays.asList(address, value)
            	);
            if (isSymbolic) {
            	memoryUnit.add(traceFileController.getSymbolicMarker());
            }
            memoryListModel.addElement(memoryUnit);
            
            traceFileController.addEntryStateMemory(address, value, isSymbolic);
		});
	}
	
	private void setupBtnRemoveMemory(JButton btnRemoveMemory) {
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
			for (int i = selectedIndices.length-1; i >= 0; i--) {
				memoryListModel.remove(selectedIndices[i]);
			}
		});
	}
	
	private void setupBtnCreateInitTraceFile(JButton btnCreateInitTraceFile) {
		btnCreateInitTraceFile.addActionListener(e -> {
			traceFileController.createTraceFile(panel);
		});
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
