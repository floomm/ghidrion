package ghidrion;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GhidraScriptService;
import ghidra.framework.plugintool.Plugin;
import resources.Icons;

public class GhidrionProvider extends ComponentProvider {
	
	private Plugin plugin;
	
	private GhidraScriptService scriptService;
	
	private JPanel panel;
	private DockingAction action;

	public GhidrionProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		JTextArea textArea = new JTextArea(5, 25);
		textArea.setEditable(false);
		panel.add(new JScrollPane(textArea));
		setVisible(true);
	}

	// TODO: Customize actions
	private void createActions() {
		action = new DockingAction("My Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				scriptService = ServiceHelper.getService(plugin.getTool(), GhidraScriptService.class);
				scriptService.runScript("MorionTraceColorizerScript.java", null);
			}
		};
		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
