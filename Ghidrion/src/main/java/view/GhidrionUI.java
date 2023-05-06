package view;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;

import ghidra.program.model.address.Address;

import javax.swing.border.EtchedBorder;
import java.awt.Color;
import java.awt.Container;
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
import javax.swing.JList;
import javax.swing.ListSelectionModel;

public class GhidrionUI {

	private JFrame frame;
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
	protected JButton btnDisplayTrace = new JButton("Import and Display");
	protected JButton btnChooseTraceColor = new JButton("Color");
	protected JScrollPane scrollPaneTraces = new JScrollPane();
	protected JButton btnRemoveTraces = new JButton("Remove selected traces");
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

	public Container getContentPane() {
		return frame.getContentPane();
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
		gridBagLayout.columnWidths = new int[] { 0, 0 };
		gridBagLayout.rowHeights = new int[] { 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 1.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 1.0, Double.MIN_VALUE };
		frame.getContentPane().setLayout(gridBagLayout);
		JPanel panelCreateTraceFile = new JPanel();
		panelCreateTraceFile.setBorder(new TitledBorder(
				new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)),
				"Create init trace file", TitledBorder.LEADING, TitledBorder.ABOVE_TOP, null, new Color(0, 0, 0)));
		GridBagLayout gbl_panelCreateTraceFile = new GridBagLayout();
		gbl_panelCreateTraceFile.columnWidths = new int[] { 956, 0 };
		gbl_panelCreateTraceFile.rowHeights = new int[] { 0, 0, 0, 0, 0 };
		gbl_panelCreateTraceFile.columnWeights = new double[] { 1.0, Double.MIN_VALUE };
		gbl_panelCreateTraceFile.rowWeights = new double[] { 1.0, 0.0, 0.0, 1.0, Double.MIN_VALUE };
		panelCreateTraceFile.setLayout(gbl_panelCreateTraceFile);

		GridBagConstraints gbc_panelHooks = new GridBagConstraints();
		gbc_panelHooks.insets = new Insets(0, 0, 5, 0);
		gbc_panelHooks.fill = GridBagConstraints.BOTH;
		gbc_panelHooks.gridx = 0;
		gbc_panelHooks.gridy = 0;
		panelHooks.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Add hooks",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panelCreateTraceFile.add(panelHooks, gbc_panelHooks);
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
		panelCreateTraceFile.add(panelRegisters, gbc_panelRegisters);

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
		panelCreateTraceFile.add(panelMemory, gbc_panelMemory);

		JPanel panelButtons = new JPanel();
		GridBagConstraints gbc_panelButtons = new GridBagConstraints();
		gbc_panelButtons.fill = GridBagConstraints.BOTH;
		gbc_panelButtons.gridx = 0;
		gbc_panelButtons.gridy = 3;
		panelCreateTraceFile.add(panelButtons, gbc_panelButtons);

		panelButtons.add(btnLoadTraceFile);

		panelButtons.add(btnCreateTraceFile);

		panelButtons.add(btnClearTraceFile);
		GridBagConstraints gbc_panelCreateTraceFile = new GridBagConstraints();
		gbc_panelCreateTraceFile.anchor = GridBagConstraints.NORTHWEST;
		gbc_panelCreateTraceFile.insets = new Insets(0, 0, 5, 0);
		gbc_panelCreateTraceFile.gridx = 0;
		gbc_panelCreateTraceFile.gridy = 0;
		frame.getContentPane().add(panelCreateTraceFile, gbc_panelCreateTraceFile);

		JPanel panelDisplayTraceFile = new JPanel();
		panelDisplayTraceFile.setBorder(new TitledBorder(
				new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)),
				"Display Morion trace file", TitledBorder.LEADING, TitledBorder.ABOVE_TOP, null, new Color(0, 0, 0)));
		GridBagLayout gbl_panelDisplayTraceFile = new GridBagLayout();
		gbl_panelDisplayTraceFile.columnWidths = new int[] { 0, 0, 0, 0 };
		gbl_panelDisplayTraceFile.rowHeights = new int[] { 0, 50, 0, 0 };
		gbl_panelDisplayTraceFile.columnWeights = new double[] { 0.0, 0.0, 1.0, Double.MIN_VALUE };
		gbl_panelDisplayTraceFile.rowWeights = new double[] { 0.0, 1.0, 0.0, Double.MIN_VALUE };
		panelDisplayTraceFile.setLayout(gbl_panelDisplayTraceFile);

		GridBagConstraints gbc_btnDisplayTrace = new GridBagConstraints();
		gbc_btnDisplayTrace.insets = new Insets(0, 0, 5, 5);
		gbc_btnDisplayTrace.gridx = 0;
		gbc_btnDisplayTrace.gridy = 0;
		panelDisplayTraceFile.add(btnDisplayTrace, gbc_btnDisplayTrace);

		GridBagConstraints gbc_btnChooseTraceColor = new GridBagConstraints();
		gbc_btnChooseTraceColor.insets = new Insets(0, 0, 5, 5);
		gbc_btnChooseTraceColor.gridx = 1;
		gbc_btnChooseTraceColor.gridy = 0;
		panelDisplayTraceFile.add(btnChooseTraceColor, gbc_btnChooseTraceColor);

		GridBagConstraints gbc_scrollPaneTraces = new GridBagConstraints();
		gbc_scrollPaneTraces.insets = new Insets(0, 0, 5, 0);
		gbc_scrollPaneTraces.gridwidth = 3;
		gbc_scrollPaneTraces.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneTraces.gridx = 0;
		gbc_scrollPaneTraces.gridy = 1;
		panelDisplayTraceFile.add(scrollPaneTraces, gbc_scrollPaneTraces);

		GridBagConstraints gbc_btnRemoveTraces = new GridBagConstraints();
		gbc_btnRemoveTraces.insets = new Insets(0, 0, 0, 5);
		gbc_btnRemoveTraces.gridx = 0;
		gbc_btnRemoveTraces.gridy = 2;
		panelDisplayTraceFile.add(btnRemoveTraces, gbc_btnRemoveTraces);
		GridBagConstraints gbc_panelDisplayTraceFile = new GridBagConstraints();
		gbc_panelDisplayTraceFile.insets = new Insets(0, 0, 5, 0);
		gbc_panelDisplayTraceFile.fill = GridBagConstraints.BOTH;
		gbc_panelDisplayTraceFile.gridx = 0;
		gbc_panelDisplayTraceFile.gridy = 1;
		frame.getContentPane().add(panelDisplayTraceFile, gbc_panelDisplayTraceFile);
	}
}
