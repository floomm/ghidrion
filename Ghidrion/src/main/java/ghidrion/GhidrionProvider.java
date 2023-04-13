package ghidrion;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GhidraScriptService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import resources.Icons;

public class GhidrionProvider extends ComponentProvider {
	
	private static final int DEFAULT_BASE_ADDRESS = 0x00400000;
	private Plugin plugin;
	private Program currentProgram;
	private FlatProgramAPI flatAPI;
	
	private GhidraScriptService scriptService;
	
	private JPanel panel;
	private DockingAction action;
	private JTextField addressTextField;

	public GhidrionProvider(Plugin plugin, String owner, Program currentProgram) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		this.currentProgram = currentProgram;
		if (currentProgram != null) {
			this.flatAPI = new FlatProgramAPI(currentProgram);
		}

		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		JTextArea textArea = new JTextArea(5, 25);
		textArea.setEditable(false);
		panel.add(new JScrollPane(textArea));
		
		addressTextField = new JTextField(String.format("0x%08X", DEFAULT_BASE_ADDRESS));
		addressTextField.setBorder(BorderFactory.createLineBorder(Color.BLUE));
		panel.add(addressTextField);
		setVisible(true);
	}

	// Customize actions
	private void createActions() {
		action = new DockingAction("My Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int baseAddress = Integer.valueOf(addressTextField.getText().substring(2));
				setBaseAddress(baseAddress);
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
	
	private void setBaseAddress(int offset) {
		if (currentProgram.getImageBase().getOffset() != offset) {
			Address baseAddress = flatAPI.toAddr(offset);
			int id = currentProgram.startTransaction("Set base address");
			try {
				currentProgram.setImageBase(baseAddress, true);
			} catch (AddressOverflowException | LockException | IllegalStateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				Msg.error(this, "Could not set image base");
			}
			currentProgram.endTransaction(id, true);
		}
	}

	public void setProgram(Program currentProgram) {
		this.currentProgram = currentProgram;
		this.flatAPI = new FlatProgramAPI(currentProgram);
	}

}
