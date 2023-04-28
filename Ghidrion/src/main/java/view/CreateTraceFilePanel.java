package view;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JPanel;

import model.MorionTraceFile;

public class CreateTraceFilePanel extends JPanel {
	
	private MorionTraceFile traceFile = new MorionTraceFile();
	
	private HooksPanel hooksPanel = new HooksPanel(this);
	private StatesPanel statesPanel = new StatesPanel(this);

	public CreateTraceFilePanel() {
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		add(hooksPanel);
		add(statesPanel);
		
		JButton createButton = new JButton("Create Morion trace file");
		createButton.addActionListener(e -> {
			// TODO: Convert traceFile to yaml
		});
	}
	
	public void init() {
		// TODO
	}
	
	public void addHook(String libraryName, String functionName, String entryAddress, String leaveAddress, String targetAddress, String mode) {
		traceFile.addHook(libraryName, functionName, entryAddress, leaveAddress, targetAddress, mode);
	}
	
	public void addEntryStateRegister(String name, String value, boolean isSymbolic) {
		traceFile.addEntryStateRegister(name, value, isSymbolic);
	}
	
	public void addEntryStateMemory(String address, String value, boolean isSymbolic) {
		traceFile.addEntryStateMemory(address, value, isSymbolic);
	}

}
