package view;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;

import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import javax.swing.JTabbedPane;

import ghidrion.GhidrionPlugin;
import model.MorionTraceFile;

public class GhidrionUI {

	private JFrame frame;
	private JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
	private JPanel panelCreateTraceFile;
	private JPanel panelDisplayTraceFile;

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

	public GhidrionUI() {
		initialize();
	}

	/**
	 * Create the application.
	 * 
	 * @param plugin
	 */
	public GhidrionUI(GhidrionPlugin plugin, MorionTraceFile traceFile) {
		this.panelCreateTraceFile = new CreateTraceFilePanel(plugin, traceFile);
		this.panelDisplayTraceFile = new DisplayTraceFilePanel(plugin);
		initialize();
	}

	public JTabbedPane getTabbedPane() {
		return tabbedPane;
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 1000, 800);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 0, 0 };
		gridBagLayout.rowHeights = new int[] { 0, 0 };
		gridBagLayout.columnWeights = new double[] { 1.0, Double.MIN_VALUE };
		gridBagLayout.rowWeights = new double[] { 0.0, Double.MIN_VALUE };
		frame.getContentPane().setLayout(gridBagLayout);

		GridBagConstraints gbc_tabbedPane = new GridBagConstraints();
		gbc_tabbedPane.fill = GridBagConstraints.BOTH;
		gbc_tabbedPane.gridx = 0;
		gbc_tabbedPane.gridy = 0;
		frame.getContentPane().add(tabbedPane, gbc_tabbedPane);

		tabbedPane.addTab("Create Init Trace File", null, panelCreateTraceFile, null);

		tabbedPane.addTab("Display Trace", null, panelDisplayTraceFile, null);
	}
}
