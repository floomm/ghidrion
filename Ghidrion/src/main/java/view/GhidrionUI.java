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
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JScrollPane;

public class GhidrionUI {

	private JFrame frame;
	private JTextField textFieldLibrary;
	private JTextField textFieldFunction;
	private JTextField textFieldEntry;
	private JTextField textFieldLeave;
	private JTextField textFieldTarget;
	private JTextField textFieldRegisterName;
	private JTextField textFieldRegisterValue;
	private JTextField textFieldMemoryAddress;
	private JTextField textFieldMemoryValue;

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
		JPanel panelCreateTraceFile = new JPanel();
		panelCreateTraceFile.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Create init trace file", TitledBorder.LEADING, TitledBorder.ABOVE_TOP, null, new Color(0, 0, 0)));
		
		JPanel panelDisplayTraceFile = new JPanel();
		panelDisplayTraceFile.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Display Morion trace file", TitledBorder.LEADING, TitledBorder.ABOVE_TOP, null, new Color(0, 0, 0)));
		GroupLayout groupLayout = new GroupLayout(frame.getContentPane());
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
		gbl_panelCreateTraceFile.rowHeights = new int[]{65, 65, 65, 0, 0};
		gbl_panelCreateTraceFile.columnWeights = new double[]{0.0, Double.MIN_VALUE};
		gbl_panelCreateTraceFile.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panelCreateTraceFile.setLayout(gbl_panelCreateTraceFile);
		
		JPanel hooksPanel = new JPanel();
		hooksPanel.setBorder(new TitledBorder(null, "Add hook", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagLayout gbl_hooksPanel = new GridBagLayout();
		gbl_hooksPanel.columnWidths = new int[]{0, 0, 0, 0, 0, 0, 0, 0};
		gbl_hooksPanel.rowHeights = new int[]{0, 0, 75, 0};
		gbl_hooksPanel.columnWeights = new double[]{1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, Double.MIN_VALUE};
		gbl_hooksPanel.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
		hooksPanel.setLayout(gbl_hooksPanel);
		
		JLabel lblLibrary = new JLabel("Library name");
		GridBagConstraints gbc_lblLibrary = new GridBagConstraints();
		gbc_lblLibrary.insets = new Insets(0, 0, 5, 5);
		gbc_lblLibrary.gridx = 1;
		gbc_lblLibrary.gridy = 0;
		hooksPanel.add(lblLibrary, gbc_lblLibrary);
		
		JLabel lblFunction = new JLabel("Function name");
		GridBagConstraints gbc_lblFunction = new GridBagConstraints();
		gbc_lblFunction.insets = new Insets(0, 0, 5, 5);
		gbc_lblFunction.gridx = 2;
		gbc_lblFunction.gridy = 0;
		hooksPanel.add(lblFunction, gbc_lblFunction);
		
		JLabel lblEntry = new JLabel("Entry address");
		GridBagConstraints gbc_lblEntry = new GridBagConstraints();
		gbc_lblEntry.insets = new Insets(0, 0, 5, 5);
		gbc_lblEntry.gridx = 3;
		gbc_lblEntry.gridy = 0;
		hooksPanel.add(lblEntry, gbc_lblEntry);
		
		JLabel lblLeave = new JLabel("Leave address");
		GridBagConstraints gbc_lblLeave = new GridBagConstraints();
		gbc_lblLeave.insets = new Insets(0, 0, 5, 5);
		gbc_lblLeave.gridx = 4;
		gbc_lblLeave.gridy = 0;
		hooksPanel.add(lblLeave, gbc_lblLeave);
		
		JLabel lblTarget = new JLabel("Target address");
		GridBagConstraints gbc_lblTarget = new GridBagConstraints();
		gbc_lblTarget.insets = new Insets(0, 0, 5, 5);
		gbc_lblTarget.gridx = 5;
		gbc_lblTarget.gridy = 0;
		hooksPanel.add(lblTarget, gbc_lblTarget);
		
		JLabel lblMode = new JLabel("Mode");
		GridBagConstraints gbc_lblMode = new GridBagConstraints();
		gbc_lblMode.insets = new Insets(0, 0, 5, 0);
		gbc_lblMode.gridx = 6;
		gbc_lblMode.gridy = 0;
		hooksPanel.add(lblMode, gbc_lblMode);
		
		JButton btnAddHook = new JButton("Add");
		GridBagConstraints gbc_btnAddHook = new GridBagConstraints();
		gbc_btnAddHook.insets = new Insets(0, 0, 5, 5);
		gbc_btnAddHook.gridx = 0;
		gbc_btnAddHook.gridy = 1;
		hooksPanel.add(btnAddHook, gbc_btnAddHook);
		
		textFieldLibrary = new JTextField();
		GridBagConstraints gbc_textFieldLibrary = new GridBagConstraints();
		gbc_textFieldLibrary.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldLibrary.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldLibrary.gridx = 1;
		gbc_textFieldLibrary.gridy = 1;
		hooksPanel.add(textFieldLibrary, gbc_textFieldLibrary);
		textFieldLibrary.setColumns(10);
		
		textFieldFunction = new JTextField();
		GridBagConstraints gbc_textFieldFunction = new GridBagConstraints();
		gbc_textFieldFunction.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldFunction.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldFunction.gridx = 2;
		gbc_textFieldFunction.gridy = 1;
		hooksPanel.add(textFieldFunction, gbc_textFieldFunction);
		textFieldFunction.setColumns(10);
		
		textFieldEntry = new JTextField();
		textFieldEntry.setText("0x");
		GridBagConstraints gbc_textFieldEntry = new GridBagConstraints();
		gbc_textFieldEntry.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldEntry.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldEntry.gridx = 3;
		gbc_textFieldEntry.gridy = 1;
		hooksPanel.add(textFieldEntry, gbc_textFieldEntry);
		textFieldEntry.setColumns(10);
		
		textFieldLeave = new JTextField();
		textFieldLeave.setText("0x");
		GridBagConstraints gbc_textFieldLeave = new GridBagConstraints();
		gbc_textFieldLeave.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldLeave.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldLeave.gridx = 4;
		gbc_textFieldLeave.gridy = 1;
		hooksPanel.add(textFieldLeave, gbc_textFieldLeave);
		textFieldLeave.setColumns(10);
		
		textFieldTarget = new JTextField();
		textFieldTarget.setText("0x");
		GridBagConstraints gbc_textFieldTarget = new GridBagConstraints();
		gbc_textFieldTarget.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldTarget.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldTarget.gridx = 5;
		gbc_textFieldTarget.gridy = 1;
		hooksPanel.add(textFieldTarget, gbc_textFieldTarget);
		textFieldTarget.setColumns(10);
		
		JComboBox comboBoxHookMode = new JComboBox();
		comboBoxHookMode.setModel(new DefaultComboBoxModel(new String[] {"model", "skip", "taint"}));
		GridBagConstraints gbc_comboBoxHookMode = new GridBagConstraints();
		gbc_comboBoxHookMode.insets = new Insets(0, 0, 5, 0);
		gbc_comboBoxHookMode.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBoxHookMode.gridx = 6;
		gbc_comboBoxHookMode.gridy = 1;
		hooksPanel.add(comboBoxHookMode, gbc_comboBoxHookMode);
		GridBagConstraints gbc_hooksPanel = new GridBagConstraints();
		gbc_hooksPanel.fill = GridBagConstraints.BOTH;
		gbc_hooksPanel.insets = new Insets(0, 0, 5, 0);
		gbc_hooksPanel.gridx = 0;
		gbc_hooksPanel.gridy = 0;
		panelCreateTraceFile.add(hooksPanel, gbc_hooksPanel);
		
		JScrollPane scrollPaneHooks = new JScrollPane();
		GridBagConstraints gbc_scrollPaneHooks = new GridBagConstraints();
		gbc_scrollPaneHooks.gridwidth = 7;
		gbc_scrollPaneHooks.insets = new Insets(0, 0, 0, 5);
		gbc_scrollPaneHooks.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneHooks.gridx = 0;
		gbc_scrollPaneHooks.gridy = 2;
		hooksPanel.add(scrollPaneHooks, gbc_scrollPaneHooks);
		
		JPanel registersPanel = new JPanel();
		registersPanel.setBorder(new TitledBorder(null, "Add register", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagLayout gbl_registersPanel = new GridBagLayout();
		gbl_registersPanel.columnWidths = new int[]{0, 0, 0, 0, 0};
		gbl_registersPanel.rowHeights = new int[]{0, 0, 75, 0};
		gbl_registersPanel.columnWeights = new double[]{1.0, 1.0, 1.0, 0.0, Double.MIN_VALUE};
		gbl_registersPanel.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
		registersPanel.setLayout(gbl_registersPanel);
		
		JLabel lblRegisterName = new JLabel("Name");
		GridBagConstraints gbc_lblRegisterName = new GridBagConstraints();
		gbc_lblRegisterName.insets = new Insets(0, 0, 5, 5);
		gbc_lblRegisterName.gridx = 1;
		gbc_lblRegisterName.gridy = 0;
		registersPanel.add(lblRegisterName, gbc_lblRegisterName);
		
		JLabel lblRegisterValue = new JLabel("Value");
		GridBagConstraints gbc_lblRegisterValue = new GridBagConstraints();
		gbc_lblRegisterValue.insets = new Insets(0, 0, 5, 5);
		gbc_lblRegisterValue.gridx = 2;
		gbc_lblRegisterValue.gridy = 0;
		registersPanel.add(lblRegisterValue, gbc_lblRegisterValue);
		
		JLabel lblIsRegisterSymbolic = new JLabel("Symbolic?");
		GridBagConstraints gbc_lblIsRegisterSymbolic = new GridBagConstraints();
		gbc_lblIsRegisterSymbolic.insets = new Insets(0, 0, 5, 0);
		gbc_lblIsRegisterSymbolic.gridx = 3;
		gbc_lblIsRegisterSymbolic.gridy = 0;
		registersPanel.add(lblIsRegisterSymbolic, gbc_lblIsRegisterSymbolic);
		
		JButton btnAddRegister = new JButton("Add");
		GridBagConstraints gbc_btnAddRegister = new GridBagConstraints();
		gbc_btnAddRegister.insets = new Insets(0, 0, 5, 5);
		gbc_btnAddRegister.gridx = 0;
		gbc_btnAddRegister.gridy = 1;
		registersPanel.add(btnAddRegister, gbc_btnAddRegister);
		
		textFieldRegisterName = new JTextField();
		GridBagConstraints gbc_textFieldRegisterName = new GridBagConstraints();
		gbc_textFieldRegisterName.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldRegisterName.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldRegisterName.gridx = 1;
		gbc_textFieldRegisterName.gridy = 1;
		registersPanel.add(textFieldRegisterName, gbc_textFieldRegisterName);
		textFieldRegisterName.setColumns(10);
		
		textFieldRegisterValue = new JTextField();
		textFieldRegisterValue.setText("0x");
		GridBagConstraints gbc_textFieldRegisterValue = new GridBagConstraints();
		gbc_textFieldRegisterValue.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldRegisterValue.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldRegisterValue.gridx = 2;
		gbc_textFieldRegisterValue.gridy = 1;
		registersPanel.add(textFieldRegisterValue, gbc_textFieldRegisterValue);
		textFieldRegisterValue.setColumns(10);
		
		JCheckBox chckbxIsRegisterSymbolic = new JCheckBox("");
		GridBagConstraints gbc_chckbxIsRegisterSymbolic = new GridBagConstraints();
		gbc_chckbxIsRegisterSymbolic.insets = new Insets(0, 0, 5, 0);
		gbc_chckbxIsRegisterSymbolic.gridx = 3;
		gbc_chckbxIsRegisterSymbolic.gridy = 1;
		registersPanel.add(chckbxIsRegisterSymbolic, gbc_chckbxIsRegisterSymbolic);
		GridBagConstraints gbc_registersPanel = new GridBagConstraints();
		gbc_registersPanel.fill = GridBagConstraints.BOTH;
		gbc_registersPanel.insets = new Insets(0, 0, 5, 0);
		gbc_registersPanel.gridx = 0;
		gbc_registersPanel.gridy = 1;
		panelCreateTraceFile.add(registersPanel, gbc_registersPanel);
		
		JScrollPane scrollPaneRegisters = new JScrollPane();
		GridBagConstraints gbc_scrollPaneRegisters = new GridBagConstraints();
		gbc_scrollPaneRegisters.gridwidth = 4;
		gbc_scrollPaneRegisters.insets = new Insets(0, 0, 0, 5);
		gbc_scrollPaneRegisters.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneRegisters.gridx = 0;
		gbc_scrollPaneRegisters.gridy = 2;
		registersPanel.add(scrollPaneRegisters, gbc_scrollPaneRegisters);
		
		JPanel memoryPanel = new JPanel();
		memoryPanel.setBorder(new TitledBorder(null, "Add memory", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagLayout gbl_memoryPanel = new GridBagLayout();
		gbl_memoryPanel.columnWidths = new int[]{0, 0, 0, 0, 0};
		gbl_memoryPanel.rowHeights = new int[]{0, 0, 75, 0};
		gbl_memoryPanel.columnWeights = new double[]{1.0, 1.0, 1.0, 0.0, Double.MIN_VALUE};
		gbl_memoryPanel.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
		memoryPanel.setLayout(gbl_memoryPanel);
		
		JLabel lblMemoryAddress = new JLabel("Address");
		GridBagConstraints gbc_lblMemoryAddress = new GridBagConstraints();
		gbc_lblMemoryAddress.insets = new Insets(0, 0, 5, 5);
		gbc_lblMemoryAddress.gridx = 1;
		gbc_lblMemoryAddress.gridy = 0;
		memoryPanel.add(lblMemoryAddress, gbc_lblMemoryAddress);
		
		JLabel lblMemoryValue = new JLabel("Value");
		GridBagConstraints gbc_lblMemoryValue = new GridBagConstraints();
		gbc_lblMemoryValue.insets = new Insets(0, 0, 5, 5);
		gbc_lblMemoryValue.gridx = 2;
		gbc_lblMemoryValue.gridy = 0;
		memoryPanel.add(lblMemoryValue, gbc_lblMemoryValue);
		
		JLabel lblIsMemorySymbolic = new JLabel("Symbolic?");
		GridBagConstraints gbc_lblIsMemorySymbolic = new GridBagConstraints();
		gbc_lblIsMemorySymbolic.insets = new Insets(0, 0, 5, 0);
		gbc_lblIsMemorySymbolic.gridx = 3;
		gbc_lblIsMemorySymbolic.gridy = 0;
		memoryPanel.add(lblIsMemorySymbolic, gbc_lblIsMemorySymbolic);
		
		JButton btnAddMemory = new JButton("Add");
		GridBagConstraints gbc_btnAddMemory = new GridBagConstraints();
		gbc_btnAddMemory.insets = new Insets(0, 0, 5, 5);
		gbc_btnAddMemory.gridx = 0;
		gbc_btnAddMemory.gridy = 1;
		memoryPanel.add(btnAddMemory, gbc_btnAddMemory);
		
		textFieldMemoryAddress = new JTextField();
		textFieldMemoryAddress.setText("0x");
		GridBagConstraints gbc_textFieldMemoryAddress = new GridBagConstraints();
		gbc_textFieldMemoryAddress.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldMemoryAddress.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldMemoryAddress.gridx = 1;
		gbc_textFieldMemoryAddress.gridy = 1;
		memoryPanel.add(textFieldMemoryAddress, gbc_textFieldMemoryAddress);
		textFieldMemoryAddress.setColumns(10);
		
		textFieldMemoryValue = new JTextField();
		textFieldMemoryValue.setText("0x");
		GridBagConstraints gbc_textFieldMemoryValue = new GridBagConstraints();
		gbc_textFieldMemoryValue.insets = new Insets(0, 0, 5, 5);
		gbc_textFieldMemoryValue.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldMemoryValue.gridx = 2;
		gbc_textFieldMemoryValue.gridy = 1;
		memoryPanel.add(textFieldMemoryValue, gbc_textFieldMemoryValue);
		textFieldMemoryValue.setColumns(10);
		
		JCheckBox chckbxIsMemorySymbolic = new JCheckBox("");
		GridBagConstraints gbc_chckbxIsMemorySymbolic = new GridBagConstraints();
		gbc_chckbxIsMemorySymbolic.insets = new Insets(0, 0, 5, 0);
		gbc_chckbxIsMemorySymbolic.gridx = 3;
		gbc_chckbxIsMemorySymbolic.gridy = 1;
		memoryPanel.add(chckbxIsMemorySymbolic, gbc_chckbxIsMemorySymbolic);
		GridBagConstraints gbc_memoryPanel = new GridBagConstraints();
		gbc_memoryPanel.fill = GridBagConstraints.BOTH;
		gbc_memoryPanel.insets = new Insets(0, 0, 5, 0);
		gbc_memoryPanel.gridx = 0;
		gbc_memoryPanel.gridy = 2;
		panelCreateTraceFile.add(memoryPanel, gbc_memoryPanel);
		
		JScrollPane scrollPaneMemory = new JScrollPane();
		GridBagConstraints gbc_scrollPaneMemory = new GridBagConstraints();
		gbc_scrollPaneMemory.gridwidth = 4;
		gbc_scrollPaneMemory.insets = new Insets(0, 0, 0, 5);
		gbc_scrollPaneMemory.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneMemory.gridx = 0;
		gbc_scrollPaneMemory.gridy = 2;
		memoryPanel.add(scrollPaneMemory, gbc_scrollPaneMemory);
		
		JButton btnCreateInitTraceFile = new JButton("Create");
		GridBagConstraints gbc_btnCreateInitTraceFile = new GridBagConstraints();
		gbc_btnCreateInitTraceFile.fill = GridBagConstraints.VERTICAL;
		gbc_btnCreateInitTraceFile.gridx = 0;
		gbc_btnCreateInitTraceFile.gridy = 3;
		panelCreateTraceFile.add(btnCreateInitTraceFile, gbc_btnCreateInitTraceFile);

		/*
		 * WHEN UPDATING THE UI, COPY UNTIL HERE
		 */
		frame.getContentPane().setLayout(groupLayout);
	}
}
