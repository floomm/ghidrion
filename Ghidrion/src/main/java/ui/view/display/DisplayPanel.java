package ui.view.display;

import javax.swing.JPanel;

import ui.model.DiffViewTableModel;
import util.observable.ObservableSet;

import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;

import ui.ctrl.DisplayController;

/**
 * UI for the Trace File Display part of the plugin.
 */
public class DisplayPanel extends JPanel {
	private final DisplayController controller;

	private final JButton btnDisplayTrace = new JButton("Import and Display");
	private final JButton btnChooseTraceColor = new JButton("Color");
	private final JButton btnClearTrace = new JButton("Clear Trace");
	private final JTable tableDiffViewRegisters = new JTable();
	private final JScrollPane scrollPaneDiffViewRegisters = new JScrollPane(tableDiffViewRegisters);
	private final JTable tableDiffViewMemory = new JTable();
	private final JScrollPane scrollPaneDiffViewMemory = new JScrollPane(tableDiffViewMemory);
	private final JTabbedPane tabbedPaneDiffView = new JTabbedPane(JTabbedPane.TOP);

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
		btnChooseTraceColor.setOpaque(true);

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
		btnDisplayTrace.addActionListener(e -> controller.loadTraceFile(this));
		btnClearTrace.addActionListener(e -> controller.clearTrace());
		btnChooseTraceColor.addActionListener(e -> controller.updateTraceColor(this));
		btnChooseTraceColor.setBackground(controller.getTraceColor().getColor());
		controller.getTraceColor().addObserver(color -> btnChooseTraceColor.setBackground(color));
		setupDiffViews();
	}

	private void setupDiffViews() {
		DiffViewTableModel memoryModel = new DiffViewTableModel(new ObservableSet<>(),
				controller.getTraceFile().getEntryMemory(),
				controller.getTraceFile().getLeaveMemory());
		tableDiffViewMemory.setModel(memoryModel);
		tableDiffViewMemory.setCellSelectionEnabled(false);
		memoryModel.setColumnHeaders(tableDiffViewMemory.getColumnModel());

		DiffViewTableModel registerModel = new DiffViewTableModel(new ObservableSet<>(),
				controller.getTraceFile().getEntryRegisters(),
				controller.getTraceFile().getLeaveRegisters());
		tableDiffViewRegisters.setModel(registerModel);
		tableDiffViewRegisters.setCellSelectionEnabled(false);
		registerModel.setColumnHeaders(tableDiffViewRegisters.getColumnModel());
	}
}
