package view;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;

public class HooksPanel extends JPanel {
	
	private JTextField libraryField;
    private JTextField functionField;
    private JTextField entryAddressField;
    private JTextField leaveAddressField;
    private JTextField targetAddressField;
    private JComboBox<String> comboBox;
    private DefaultListModel<ArrayList<String>> hookListModel = new DefaultListModel<>();
	private JList<ArrayList<String>> hookList = new JList<>(hookListModel);
	
	public HooksPanel(CreateTraceFilePanel parent) {
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.X_AXIS));

        JLabel libraryLabel = new JLabel("Library: ");
        libraryField = new JTextField(10);
        inputPanel.add(libraryLabel);
        inputPanel.add(libraryField);

        JLabel functionLabel = new JLabel("Function: ");
        functionField = new JTextField(10);
        inputPanel.add(functionLabel);
        inputPanel.add(functionField);

        JLabel entryAddressLabel = new JLabel("Entry address: ");
        entryAddressField = new HexTextField(10);
        inputPanel.add(entryAddressLabel);
        inputPanel.add(entryAddressField);

        JLabel leaveAddressLabel = new JLabel("Leave address: ");
        leaveAddressField = new HexTextField(10);
        inputPanel.add(leaveAddressLabel);
        inputPanel.add(leaveAddressField);

        JLabel targetAddressLabel = new JLabel("Target address: ");
        targetAddressField = new HexTextField(10);
        inputPanel.add(targetAddressLabel);
        inputPanel.add(targetAddressField);

        String[] comboBoxOptions = {"model", "skip"};
        comboBox = new JComboBox<>(comboBoxOptions);
        inputPanel.add(comboBox);

        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> {
            String libraryName = libraryField.getText();
            String functionName = functionField.getText();
            String entryAddress = entryAddressField.getText();
            String leaveAddress = leaveAddressField.getText();
            String targetAddress = targetAddressField.getText();
            String mode = (String) comboBox.getSelectedItem();

            ArrayList<String> hook = new ArrayList<>(
            		Arrays.asList(libraryName, functionName, entryAddress, leaveAddress, targetAddress, mode)
            	);
            
            hookListModel.addElement(hook);
            
            parent.addHook(libraryName, functionName, entryAddress, leaveAddress, targetAddress, mode);
        });
        inputPanel.add(addButton);
        add(inputPanel);

        JScrollPane scrollPane = new JScrollPane(hookList);
        add(scrollPane);
	}
	
	public List<List<String>> getHooks() {
		List<List<String>> hooks = new ArrayList<>();
		for (int i = 0; i < hookListModel.getSize(); i++) {
			hooks.add(hookListModel.getElementAt(i));
		}
		return hooks;
	}
}
