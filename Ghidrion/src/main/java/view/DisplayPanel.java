package view;

import javax.swing.JPanel;
import ctrl.DisplayController;
import ctrl.TraceFileNotFoundException;
import ghidra.util.Msg;
import model.DiffEntry;
import model.MorionTraceFile;
import util.DiffViewTableModel;
import util.FileHelper;
import util.ObservableSet;
import util.YamlConverterException;
import util.YamlToTraceFileConverter;

import java.awt.Color;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import javax.swing.JButton;
import javax.swing.JColorChooser;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;

public class DisplayPanel extends JPanel {
	private final DisplayController controller;
	private final MorionTraceFile traceFile = new MorionTraceFile();

	private final JButton btnDisplayTrace = new JButton("Import and Display");
	private final JButton btnChooseTraceColor = new JButton("Color");
	private final JButton btnClearTrace = new JButton("Clear Trace");
	private final JTable tableDiffViewRegisters = new JTable();
	private final JScrollPane scrollPaneDiffViewRegisters = new JScrollPane(tableDiffViewRegisters);
	private final JTable tableDiffViewMemory = new JTable();
	private final JScrollPane scrollPaneDiffViewMemory = new JScrollPane(tableDiffViewMemory);
	private final JTabbedPane tabbedPaneDiffView = new JTabbedPane(JTabbedPane.TOP);

	private Color traceColor = Color.GREEN;

	public DisplayPanel(DisplayController controller) {
		this.controller = controller;
		init();
		setupComponents();
	}

	/**
	 * This constructor is solely for debugging the UI.
	 * Do NOT use for the plugin.
	 */
	public DisplayPanel() {
		this.controller = null;
		init();
	}

	private void init() {
		GridBagLayout gbl_panelDisplayTraceFile = new GridBagLayout();
		gbl_panelDisplayTraceFile.columnWidths = new int[] { 0, 0, 0 };
		gbl_panelDisplayTraceFile.rowHeights = new int[] { 0, 1 };
		gbl_panelDisplayTraceFile.columnWeights = new double[] { 1.0, 1.0, 1.0 };
		gbl_panelDisplayTraceFile.rowWeights = new double[] { 0.0, 1.0 };
		setLayout(gbl_panelDisplayTraceFile);

		GridBagConstraints gbc_btnDisplayTrace = new GridBagConstraints();
		gbc_btnDisplayTrace.gridx = 0;
		gbc_btnDisplayTrace.gridy = 0;
		add(btnDisplayTrace, gbc_btnDisplayTrace);

		GridBagConstraints gbc_btnChooseTraceColor = new GridBagConstraints();
		gbc_btnChooseTraceColor.gridx = 1;
		gbc_btnChooseTraceColor.gridy = 0;
		add(btnChooseTraceColor, gbc_btnChooseTraceColor);

		GridBagConstraints gbc_btnClearTrace = new GridBagConstraints();
		gbc_btnClearTrace.gridx = 2;
		gbc_btnClearTrace.gridy = 0;
		add(btnClearTrace, gbc_btnClearTrace);

		tabbedPaneDiffView.addTab("Registers", scrollPaneDiffViewRegisters);
		tabbedPaneDiffView.addTab("Memory", scrollPaneDiffViewMemory);
		GridBagConstraints gbc_tabbedPaneDiffView = new GridBagConstraints();
		gbc_tabbedPaneDiffView.fill = GridBagConstraints.BOTH;
		gbc_tabbedPaneDiffView.gridwidth = 3;
		gbc_tabbedPaneDiffView.gridx = 0;
		gbc_tabbedPaneDiffView.gridy = 1;
		add(tabbedPaneDiffView, gbc_tabbedPaneDiffView);
	}

	private void setupComponents() {
		setupBtnDisplayTrace();
		setupBtnChooseTraceColor();
		setupBtnClearTrace();
		setupDiffViews();
	}

	private void setupDiffViews() {
		ObservableSet<DiffEntry> diffEntriesMemory = new ObservableSet<>();
		DiffViewTableModel memoryModel = new DiffViewTableModel(diffEntriesMemory, traceFile.getEntryMemory(),
				traceFile.getLeaveMemory());
		tableDiffViewMemory.setModel(memoryModel);
		tableDiffViewMemory.setCellSelectionEnabled(false);
		memoryModel.setColumnHeaders(tableDiffViewMemory.getColumnModel());

		ObservableSet<DiffEntry> diffEntriesRegister = new ObservableSet<>();
		DiffViewTableModel registerModel = new DiffViewTableModel(diffEntriesRegister, traceFile.getEntryRegisters(),
				traceFile.getLeaveRegisters());
		tableDiffViewRegisters.setModel(registerModel);
		tableDiffViewRegisters.setCellSelectionEnabled(false);
		registerModel.setColumnHeaders(tableDiffViewRegisters.getColumnModel());
	}

	private void setupBtnClearTrace() {
		btnClearTrace.addActionListener(e -> {
			controller.getPlugin().colorizerScript.decolorize();
			traceFile.clear();
		});
	}

	private void setupBtnDisplayTrace() {
		btnDisplayTrace.addActionListener(e -> {
			try {
				YamlToTraceFileConverter.toTraceFile(traceFile, FileHelper.getFileStreamToLoad(this),
						controller.getPlugin().getCurrentProgram().getAddressFactory());
			} catch (TraceFileNotFoundException ex) {
				return;
			} catch (YamlConverterException ex) {
				Msg.showError(this, this, ex.getTitle(), ex.getMessage(), ex);
				ex.printStackTrace();
			}
			controller.getPlugin().colorizerScript.colorize(traceFile, traceColor);
		});
	}

	private void setupBtnChooseTraceColor() {
		btnChooseTraceColor.setOpaque(true);
		btnChooseTraceColor.setBackground(traceColor);
		btnChooseTraceColor.addActionListener(e -> {
			Color newColor = JColorChooser.showDialog(this, "Choose a color", traceColor);
			if (newColor != null) {
				traceColor = newColor;
				btnChooseTraceColor.setBackground(traceColor);
			}
		});
	}

}
