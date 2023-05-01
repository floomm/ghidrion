package view;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;

public class StatesPanel extends JPanel {
	
	private CreateTraceFilePanel parent;
	
	public StatesPanel(CreateTraceFilePanel parent) {
		this.parent = parent;
		
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		
		RegistersPanel registersPanel = new RegistersPanel(this);
		TitledBorder borderRegistersPanel = BorderFactory.createTitledBorder("Add register");
		registersPanel.setBorder(borderRegistersPanel);
		
		MemoryPanel memoryPanel = new MemoryPanel(this);
		TitledBorder borderMemoryPanel = BorderFactory.createTitledBorder("Add memory");
		memoryPanel.setBorder(borderMemoryPanel);
		
		add(registersPanel);
		add(memoryPanel);
	}
	
	public void addEntryStateRegister(String name, String value, boolean isSymbolic) {
		parent.addEntryStateRegister(name, value, isSymbolic);
	}
	
	public void addEntryStateMemory(String address, String value, boolean isSymbolic) {
		parent.addEntryStateMemory(address, value, isSymbolic);
	}
	
}
