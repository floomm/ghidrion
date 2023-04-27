package view;

import javax.swing.BoxLayout;
import javax.swing.JPanel;

public class StatesPanel extends JPanel {
	
	public StatesPanel() {
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		add(new RegistersPanel());
		add(new MemoryPanel());
	}
	
}
