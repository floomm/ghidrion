package ui.view.create;

import javax.swing.JPanel;

import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;

import javax.swing.JButton;
import javax.swing.JTabbedPane;

import ui.ctrl.CreateController;

/**
 * Panel responsible for all UI for creating a YAML file. Includes parts for
 * adding hooks, memory entries, and registers.
 */
public class CreatePanel extends JPanel {
	private final CreateController controller;
	private final HookPanel panelHooks;
	private final MemoryPanel memoryPanel;
	private final RegistersPanel registersPanel;

	private final JButton btnLoadTraceFile = new JButton("Load Init Trace File");
	private final JButton btnCreateTraceFile = new JButton("Create Init Trace File");
	private final JButton btnClearTraceFile = new JButton("Clear Added Elements");
	private final JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);

	public CreatePanel(CreateController controller) {
		this.controller = controller;
		this.panelHooks = new HookPanel(controller);
		this.memoryPanel = new MemoryPanel(controller);
		this.registersPanel = new RegistersPanel(controller);
		init();
		setupComponents();
	}

	/**
	 * This constructor is solely for debugging the UI.
	 * Do NOT use for the plugin.
	 */
	public CreatePanel() {
		this.controller = null;
		this.panelHooks = new HookPanel();
		this.memoryPanel = new MemoryPanel();
		this.registersPanel = new RegistersPanel();
		init();
	}

	private void init() {
		GridBagLayout gbl_panelCreateTraceFile = new GridBagLayout();
		gbl_panelCreateTraceFile.columnWidths = new int[] { 0 };
		gbl_panelCreateTraceFile.rowHeights = new int[] { 0, 0 };
		gbl_panelCreateTraceFile.columnWeights = new double[] { 1.0 };
		gbl_panelCreateTraceFile.rowWeights = new double[] { 1.0, Double.MIN_VALUE };
		setLayout(gbl_panelCreateTraceFile);

		JPanel panelButtons = new JPanel();
		GridBagConstraints gbc_panelButtons = new GridBagConstraints();
		gbc_panelButtons.fill = GridBagConstraints.HORIZONTAL;
		gbc_panelButtons.gridx = 0;
		gbc_panelButtons.gridy = 1;
		add(panelButtons, gbc_panelButtons);

		panelButtons.add(btnLoadTraceFile);
		panelButtons.add(btnCreateTraceFile);
		panelButtons.add(btnClearTraceFile);

		GridBagConstraints gbc_tabbedPane = new GridBagConstraints();
		gbc_tabbedPane.fill = GridBagConstraints.BOTH;
		gbc_tabbedPane.gridx = 0;
		gbc_tabbedPane.gridy = 0;
		add(tabbedPane, gbc_tabbedPane);
		tabbedPane.addTab("Hooks", null, panelHooks, null);
		tabbedPane.addTab("Entry Memory", null, memoryPanel, null);
		tabbedPane.addTab("Entry Registers", null, registersPanel, null);
	}

	private void setupComponents() {
		setupBtnLoadTraceFile();
		setupBtnCreateTraceFile();
		setupBtnClearTraceFile();
	}

	private void setupBtnLoadTraceFile() {
		btnLoadTraceFile.addActionListener(e -> controller.readTraceFile(this));
	}

	private void setupBtnCreateTraceFile() {
		btnCreateTraceFile.addActionListener(e -> controller.writeTraceFile(this));
	}

	private void setupBtnClearTraceFile() {
		btnClearTraceFile.addActionListener(controller::clearTraceFileListener);
	}

}
