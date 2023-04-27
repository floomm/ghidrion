package view;

import java.util.ArrayList;
import java.util.Arrays;

import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;

public class MemoryPanel extends JPanel {
	private JTextField addressField;
	private JTextField valueField;
    private DefaultListModel<ArrayList<String>> memoryListModel = new DefaultListModel<>();
	private JList<ArrayList<String>> memoryList = new JList<>(memoryListModel);
	
	public MemoryPanel() {
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.X_AXIS));

        JLabel nameLabel = new JLabel("Memory address: ");
        addressField = new JTextField(10);
        inputPanel.add(nameLabel);
        inputPanel.add(addressField);

        JLabel valueLabel = new JLabel("Memory value: ");
        valueField = new JTextField(10);
        inputPanel.add(valueLabel);
        inputPanel.add(valueField);

        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> {
        	String name = addressField.getText();
        	String value = valueField.getText();

            ArrayList<String> memoryUnit = new ArrayList<>(
            		Arrays.asList(name, value)
            	);
            
            memoryListModel.addElement(memoryUnit);
        });
        inputPanel.add(addButton);

        add(inputPanel);

        JScrollPane scrollPane = new JScrollPane(memoryList);
        
        add(scrollPane);
	}

}
