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

public class RegistersPanel extends JPanel {
	private JTextField nameField;
	private JTextField valueField;
    private DefaultListModel<ArrayList<String>> registerListModel = new DefaultListModel<>();
	private JList<ArrayList<String>> registerList = new JList<>(registerListModel);
	
	public RegistersPanel() {
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.X_AXIS));

        JLabel nameLabel = new JLabel("Register name: ");
        nameField = new JTextField(10);
        inputPanel.add(nameLabel);
        inputPanel.add(nameField);

        JLabel valueLabel = new JLabel("Register value: ");
        valueField = new JTextField(10);
        inputPanel.add(valueLabel);
        inputPanel.add(valueField);

        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> {
        	String name = nameField.getText();
        	String value = valueField.getText();

            ArrayList<String> register = new ArrayList<>(
            		Arrays.asList(name, value)
            	);
            
            registerListModel.addElement(register);
        });
        inputPanel.add(addButton);

        add(inputPanel);

        JScrollPane scrollPane = new JScrollPane(registerList);
        
        add(scrollPane);
	}
	
}
