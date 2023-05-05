package view;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import javax.swing.border.EtchedBorder;
import java.awt.Color;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JCheckBox;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;

public class GhidrionUI {

	private JFrame frame;
	private JTextField textFieldLibrary;
	private JTextField textFieldFunction;
	private JTextField textFieldEntry;
	private JTextField textFieldLeave;
	private JTextField textFieldTarget;
	private JComboBox<String> comboBoxHookMode = new JComboBox<>();
	private JTextField textFieldRegisterName;
	private JTextField textFieldRegisterValue;
	private JCheckBox chckbxIsRegisterSymbolic = new JCheckBox("");
	private JTextField textFieldMemoryAddress;
	private JTextField textFieldMemoryValue;
	private JCheckBox chckbxIsMemorySymbolic = new JCheckBox("");

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GhidrionUI window = new GhidrionUI();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public GhidrionUI() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 1000, 800);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		/*
		 * WHEN UPDATING THE UI, COPY FROM HERE
		 */
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] {0, 0};
		gridBagLayout.rowHeights = new int[] {0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		frame.getContentPane().setLayout(gridBagLayout);
		JPanel panelCreateTraceFile = new JPanel();
		panelCreateTraceFile.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Create init trace file", TitledBorder.LEADING, TitledBorder.ABOVE_TOP, null, new Color(0, 0, 0)));
		GridBagLayout gbl_panelCreateTraceFile = new GridBagLayout();
		gbl_panelCreateTraceFile.columnWidths = new int[]{956, 0};
		gbl_panelCreateTraceFile.rowHeights = new int[] {0, 0, 0, 0, 0};
		gbl_panelCreateTraceFile.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panelCreateTraceFile.rowWeights = new double[]{0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		panelCreateTraceFile.setLayout(gbl_panelCreateTraceFile);
		
		JPanel panelHooks = new JPanel();
		panelHooks.setBorder(new TitledBorder(null, "Add hook", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagLayout gbl_panelHooks = new GridBagLayout();
		gbl_panelHooks.columnWidths = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panelHooks.rowHeights = new int[] {0, 0, 50, 0};
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
		
		comboBoxHookMode.setModel(new DefaultComboBoxModel<String>(new String[] {"model", "skip", "taint"}));
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
		gbl_panelRegisters.rowHeights = new int[] {0, 0, 50, 0};
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
		gbl_panelMemory.rowHeights = new int[] {0, 0, 50, 0};
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
		
		JPanel panelButtons = new JPanel();
		GridBagConstraints gbc_panelButtons = new GridBagConstraints();
		gbc_panelButtons.fill = GridBagConstraints.BOTH;
		gbc_panelButtons.gridx = 0;
		gbc_panelButtons.gridy = 3;
		panelCreateTraceFile.add(panelButtons, gbc_panelButtons);
		
		JButton btnLoadTraceFile = new JButton("Load");
		panelButtons.add(btnLoadTraceFile);
		
		JButton btnCreateTraceFile = new JButton("Save As");
		panelButtons.add(btnCreateTraceFile);
		
		JButton btnClearTraceFile = new JButton("Clear");
		panelButtons.add(btnClearTraceFile);
		GridBagConstraints gbc_panelCreateTraceFile = new GridBagConstraints();
		gbc_panelCreateTraceFile.anchor = GridBagConstraints.NORTHWEST;
		gbc_panelCreateTraceFile.insets = new Insets(0, 0, 5, 0);
		gbc_panelCreateTraceFile.gridx = 0;
		gbc_panelCreateTraceFile.gridy = 0;
		frame.getContentPane().add(panelCreateTraceFile, gbc_panelCreateTraceFile);
		
		JPanel panelDisplayTraceFile = new JPanel();
		panelDisplayTraceFile.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Display Morion trace file", TitledBorder.LEADING, TitledBorder.ABOVE_TOP, null, new Color(0, 0, 0)));
		GridBagLayout gbl_panelDisplayTraceFile = new GridBagLayout();
		gbl_panelDisplayTraceFile.columnWidths = new int[]{0, 0, 0, 0};
		gbl_panelDisplayTraceFile.rowHeights = new int[] {0, 50, 0, 0};
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
		GridBagConstraints gbc_panelDisplayTraceFile = new GridBagConstraints();
		gbc_panelDisplayTraceFile.fill = GridBagConstraints.BOTH;
		gbc_panelDisplayTraceFile.gridx = 0;
		gbc_panelDisplayTraceFile.gridy = 1;
		frame.getContentPane().add(panelDisplayTraceFile, gbc_panelDisplayTraceFile);
	}
}
