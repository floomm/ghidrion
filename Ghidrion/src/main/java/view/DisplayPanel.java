package view;

import javax.swing.JPanel;
import javax.swing.border.TitledBorder;

import ctrl.DisplayController;

import javax.swing.border.EtchedBorder;
import java.awt.Color;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.util.List;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JColorChooser;
import javax.swing.JList;
import javax.swing.JScrollPane;

public class DisplayPanel extends JPanel {
	private final DisplayController controller;
	
	private final JButton btnDisplayTrace = new JButton("Import and Display");
	private final JButton btnChooseTraceColor = new JButton("Color");
	private final JScrollPane scrollPaneTraces = new JScrollPane();
	private final DefaultListModel<String> traceListModel = new DefaultListModel<>();
	private final JList<String> traceList = new JList<>(traceListModel);
	private final JButton btnRemoveTraces = new JButton("Remove selected traces");

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
		setBorder(new TitledBorder(
				new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)),
				"Display Morion trace file", TitledBorder.LEADING, TitledBorder.ABOVE_TOP, null, new Color(0, 0, 0)));
		GridBagLayout gbl_panelDisplayTraceFile = new GridBagLayout();
		gbl_panelDisplayTraceFile.columnWidths = new int[] { 0, 0, 0, 0 };
		gbl_panelDisplayTraceFile.rowHeights = new int[] { 0, 50, 0, 0 };
		gbl_panelDisplayTraceFile.columnWeights = new double[] { 0.0, 0.0, 1.0, Double.MIN_VALUE };
		gbl_panelDisplayTraceFile.rowWeights = new double[] { 0.0, 1.0, 0.0, Double.MIN_VALUE };
		setLayout(gbl_panelDisplayTraceFile);

		GridBagConstraints gbc_btnDisplayTrace = new GridBagConstraints();
		gbc_btnDisplayTrace.insets = new Insets(0, 0, 5, 5);
		gbc_btnDisplayTrace.gridx = 0;
		gbc_btnDisplayTrace.gridy = 0;
		add(btnDisplayTrace, gbc_btnDisplayTrace);

		GridBagConstraints gbc_btnChooseTraceColor = new GridBagConstraints();
		gbc_btnChooseTraceColor.insets = new Insets(0, 0, 5, 5);
		gbc_btnChooseTraceColor.gridx = 1;
		gbc_btnChooseTraceColor.gridy = 0;
		add(btnChooseTraceColor, gbc_btnChooseTraceColor);

		GridBagConstraints gbc_scrollPaneTraces = new GridBagConstraints();
		gbc_scrollPaneTraces.insets = new Insets(0, 0, 5, 0);
		gbc_scrollPaneTraces.gridwidth = 3;
		gbc_scrollPaneTraces.fill = GridBagConstraints.BOTH;
		gbc_scrollPaneTraces.gridx = 0;
		gbc_scrollPaneTraces.gridy = 1;
		add(scrollPaneTraces, gbc_scrollPaneTraces);

		GridBagConstraints gbc_btnRemoveTraces = new GridBagConstraints();
		gbc_btnRemoveTraces.insets = new Insets(0, 0, 0, 5);
		gbc_btnRemoveTraces.gridx = 0;
		gbc_btnRemoveTraces.gridy = 2;
		add(btnRemoveTraces, gbc_btnRemoveTraces);
	}

	private void setupComponents() {
		setupBtnDisplayTrace();
		scrollPaneTraces.setViewportView(traceList);
		setupBtnChooseTraceColor();
		setupBtnRemoveTraces();
	}

	private void setupBtnRemoveTraces() {
		btnRemoveTraces.addActionListener(e -> {
			List<String> selectedItems = traceList.getSelectedValuesList();
			controller.getPlugin().colorizerScript.decolorize(selectedItems);

			int[] selectedIndices = traceList.getSelectedIndices();
			for (int i = selectedIndices.length - 1; i >= 0; i--) {
				traceListModel.remove(selectedIndices[i]);
			}
		});
	}

	private void setupBtnDisplayTrace() {
		btnDisplayTrace.addActionListener(e -> {
			String traceName = controller.getPlugin().colorizerScript.colorize(traceColor);
			if (traceName != null) {
				traceListModel.addElement(traceName);
			}
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
