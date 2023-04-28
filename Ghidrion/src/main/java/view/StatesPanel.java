package view;

import javax.swing.BoxLayout;
import javax.swing.JPanel;

public class StatesPanel extends JPanel {
	
	private CreateTraceFilePanel parent;
	
	public StatesPanel(CreateTraceFilePanel parent) {
		this.parent = parent;
		
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		add(new RegistersPanel(this));
		add(new MemoryPanel(this));
	}
	
	public void addEntryStateRegister(String name, String value, boolean isSymbolic) {
		parent.addEntryStateRegister(name, value, isSymbolic);
	}
	
	public void addEntryStateMemory(String address, String value, boolean isSymbolic) {
		parent.addEntryStateMemory(address, value, isSymbolic);
	}
	
}
