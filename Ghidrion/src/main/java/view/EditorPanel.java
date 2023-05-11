package view;

import javax.swing.JPanel;

import ctrl.EditorController;

import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;

import javax.swing.JButton;
import javax.swing.JTabbedPane;

public class EditorPanel extends JPanel {
	private final EditorController controller;
	private final HookPanel panelHooks;
	private final DataPanel panelData;

	private final JButton btnLoadTraceFile = new JButton("Load");
	private final JButton btnCreateTraceFile = new JButton("Save As");
	private final JButton btnClearTraceFile = new JButton("Clear");
	private final JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);

	public EditorPanel(EditorController controller) {
		this.controller = controller;
		this.panelHooks = new HookPanel(controller);
		this.panelData = new DataPanel(controller);
		init();
		setupComponents();
	}
	
	/**
	 * This constructor is solely for debugging the UI.
	 * Do NOT use for the plugin.
	 */
	public EditorPanel() {
		this.controller = null;
		this.panelHooks = new HookPanel();
		this.panelData = new DataPanel();
		init();
	}

	private void init() {
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
		tabbedPane.addTab("Data", null, panelData, null);
	}

	private void setupComponents() {
		setupBtnLoadTraceFile();
		setupBtnCreateTraceFile();
		setupBtnClearTraceFile();
	}

	private void setupBtnLoadTraceFile() {
		btnLoadTraceFile.addActionListener(e -> {
			clearTraceFile();
		});
	}

	private void setupBtnCreateTraceFile() {
		btnCreateTraceFile.addActionListener(e -> controller.writeTraceFile(this));
	}

	private void setupBtnClearTraceFile() {
		btnClearTraceFile.addActionListener(e -> clearTraceFile());
	}

	private void clearTraceFile() {
		panelData.clear();
		controller.getTraceFile().clear();
	}
}
