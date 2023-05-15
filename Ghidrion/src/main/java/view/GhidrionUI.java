package view;

import java.awt.EventQueue;

import javax.swing.JComponent;
import javax.swing.JFrame;

import javax.swing.JTabbedPane;

import ctrl.DisplayController;
import ctrl.TraceFileController;

public class GhidrionUI {

	private JFrame frame;
	private JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
	private CreatePanel panelCreate;
	private DisplayPanel panelDisplay;

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
	 * This constructor is solely for debugging the UI.
	 * Do NOT use for the plugin.
	 */
	public GhidrionUI() {
		this.panelCreate = new CreatePanel();
		this.panelDisplay = new DisplayPanel();
		initialize();
	}

	/**
	 * Create the application.
	 * 
	 * @param traceFileController controls the {@link CreatePanel}
	 * @param displayController   controls the {@link DisplayPanel}
	 */
	public GhidrionUI(TraceFileController traceFileController, DisplayController displayController) {
		this.panelCreate = new CreatePanel(traceFileController);
		this.panelDisplay = new DisplayPanel(displayController);
		initialize();
	}

	public JComponent getTabbedPane() {
		return tabbedPane;
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 1000, 800);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		frame.getContentPane().add(tabbedPane);

		tabbedPane.addTab("Create Init Trace File", null, panelCreate, null);

		tabbedPane.addTab("Display Trace", null, panelDisplay, null);
	}
}
