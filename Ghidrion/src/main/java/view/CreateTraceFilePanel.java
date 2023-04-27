package view;

import javax.swing.BoxLayout;
import javax.swing.JPanel;

public class CreateTraceFilePanel extends JPanel {
	
	public CreateTraceFilePanel() {
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		add(new HooksPanel());
		add(new StatesPanel());
	}
	
	public void init() {
		// TODO
	}

}
