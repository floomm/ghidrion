package ui.view;

import java.awt.EventQueue;

import javax.swing.JComponent;
import javax.swing.JFrame;

import javax.swing.JTabbedPane;

import ui.ctrl.CreateController;
import ui.ctrl.DisplayController;
import ui.view.create.CreatePanel;
import ui.view.display.DisplayPanel;

/**
 * The GhidrionUI class represents the user interface for the Ghidrion
 * application.
 * It has been designed to allow the user interface to be manipulated using the
 * WindowBuilder plugin from Eclipse.
 */
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
	 * @param createController  controls the {@link CreatePanel}
	 * @param displayController controls the {@link DisplayPanel}
	 */
	public GhidrionUI(CreateController createController, DisplayController displayController) {
		this.panelCreate = new CreatePanel(createController);
		this.panelDisplay = new DisplayPanel(displayController);
		initialize();
	}

	public JComponent getPanel() {
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

		tabbedPane.addTab("Create Init YAML File", null, panelCreate, null);

		tabbedPane.addTab("Analyze Traced YAML File", null, panelDisplay, null);
	}
}
