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

import model.MorionTraceFile;

public class MemoryPanel extends JPanel {
	private JTextField addressField;
	private JTextField valueField;
	private JCheckBox symbolicCheckBox;
    private DefaultListModel<ArrayList<String>> memoryListModel = new DefaultListModel<>();
	private JList<ArrayList<String>> memoryList = new JList<>(memoryListModel);
	
	public MemoryPanel(StatesPanel parent) {
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.X_AXIS));

        JLabel nameLabel = new JLabel("Memory address: ");
        addressField = new HexTextField(10);
        inputPanel.add(nameLabel);
        inputPanel.add(addressField);

        JLabel valueLabel = new JLabel("Memory value: ");
        valueField = new HexTextField(10);
        inputPanel.add(valueLabel);
        inputPanel.add(valueField);
        
        symbolicCheckBox = new JCheckBox("Is symbolic");
        inputPanel.add(symbolicCheckBox);

        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> {
        	String name = addressField.getText();
        	String value = valueField.getText();
        	boolean isSymbolic = symbolicCheckBox.isSelected();

            ArrayList<String> memoryUnit = new ArrayList<>(
            		Arrays.asList(name, value)
            	);
            
            if (isSymbolic) {
            	memoryUnit.add(MorionTraceFile.SYMBOLIC);
            }
            
            memoryListModel.addElement(memoryUnit);
            
            parent.addEntryStateMemory(name, value, isSymbolic);
        });
        inputPanel.add(addButton);

        add(inputPanel);

        JScrollPane scrollPane = new JScrollPane(memoryList);
        
        add(scrollPane);
	}

}
