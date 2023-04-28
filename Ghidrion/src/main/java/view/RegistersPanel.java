package view;

import java.util.ArrayList;
import java.util.Arrays;

import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;

import model.State;

public class RegistersPanel extends JPanel {

	private JTextField nameField;
	private JTextField valueField;
	private JCheckBox symbolicCheckBox;
    private DefaultListModel<ArrayList<String>> registerListModel = new DefaultListModel<>();
	private JList<ArrayList<String>> registerList = new JList<>(registerListModel);
	
	public RegistersPanel(StatesPanel parent) {
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
        
        symbolicCheckBox = new JCheckBox("Is symbolic");
        inputPanel.add(symbolicCheckBox);

        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> {
        	String name = nameField.getText();
        	String value = valueField.getText();
        	boolean isSymbolic = symbolicCheckBox.isSelected();

            ArrayList<String> register = new ArrayList<>(
            		Arrays.asList(name, value)
            	);
            
            if (isSymbolic) {
            	register.add(State.SYMBOLIC);
            }
            
            registerListModel.addElement(register);
            
            parent.addEntryStateRegister(name, value, isSymbolic);
        });
        inputPanel.add(addButton);
        add(inputPanel);

        JScrollPane scrollPane = new JScrollPane(registerList);
        add(scrollPane);
	}
	
}
