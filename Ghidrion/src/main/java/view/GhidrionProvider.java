package view;

import javax.swing.JPanel;

import ctrl.TraceFileController;
import docking.ComponentProvider;
import ghidra.util.Msg;
import ghidrion.GhidrionPlugin;

import java.awt.Color;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.DefaultListModel;
import javax.swing.JCheckBox;
import javax.swing.JColorChooser;

public class GhidrionProvider extends ComponentProvider {
	private GhidrionPlugin plugin;
	
	private JPanel panel;
	private GhidrionUI ui = new GhidrionUI();
	
	private TraceFileController traceFileController = new TraceFileController();

    private DefaultListModel<Map<Long,List<String>>> hookListModel = new DefaultListModel<>();
	private JList<Map<Long, List<String>>> hookList = new JList<>(hookListModel);
    private DefaultListModel<List<String>> registerListModel = new DefaultListModel<>();
	private JList<List<String>> registerList = new JList<>(registerListModel);
    private DefaultListModel<List<String>> memoryListModel = new DefaultListModel<>();
	private JList<List<String>> memoryList = new JList<>(memoryListModel);
	private DefaultListModel<String> traceListModel = new DefaultListModel<>();
	private JList<String> traceList = new JList<>(traceListModel);

	private Color traceColor = Color.GREEN;

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner) {
		super(plugin.getTool(), pluginName, owner);
		this.plugin = plugin;

		buildPanel();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel();
		setVisible(true);
		
		panel.add(ui.getContentPane());
		
		ui.textFieldEntry.setDocument(new HexDocument());
		ui.textFieldLeave.setDocument(new HexDocument());
		ui.textFieldTarget.setDocument(new HexDocument());
		ui.textFieldRegisterValue.setDocument(new HexDocument());
		ui.textFieldMemoryAddress.setDocument(new HexDocument());
		ui.textFieldMemoryValue.setDocument(new HexDocument());
		
		setupBtnAddHook(ui.btnAddHook, ui.comboBoxHookMode);
		setupBtnRemoveHook(ui.btnRemoveHook);
		ui.scrollPaneHooks.setViewportView(hookList);
		
		setupBtnAddRegister(ui.btnAddRegister, ui.chckbxIsRegisterSymbolic);
		setupBtnRemoveRegister(ui.btnRemoveRegister);
		ui.scrollPaneRegisters.setViewportView(registerList);
		
		setupBtnAddMemory(ui.btnAddMemory, ui.chckbxIsMemorySymbolic);
		setupBtnRemoveMemory(ui.btnRemoveMemory);
		ui.scrollPaneMemory.setViewportView(memoryList);
		
		setupBtnLoadTraceFile(ui.btnLoadTraceFile);
		setupBtnCreateTraceFile(ui.btnCreateTraceFile);
		setupBtnClearTraceFile(ui.btnClearTraceFile);
		
		setupBtnDisplayTrace(ui.btnDisplayTrace);
		ui.scrollPaneTraces.setViewportView(traceList);
		setupBtnChooseTraceColor(ui.btnChooseTraceColor);
		setupBtnRemoveTraces(ui.btnRemoveTraces);
	}

	private void setupBtnRemoveTraces(JButton btnRemoveTraces) {
		btnRemoveTraces.addActionListener(e -> {
			List<String> selectedItems = traceList.getSelectedValuesList();
			plugin.colorizerScript.decolorize(selectedItems);
			
			int[] selectedIndices = traceList.getSelectedIndices();
			for (int i = selectedIndices.length-1; i >= 0; i--) {
				traceListModel.remove(selectedIndices[i]);
			}
		});
	}

	private void setupBtnDisplayTrace(JButton btnDisplayTrace) {
		btnDisplayTrace.addActionListener(e -> {
			String traceName = plugin.colorizerScript.colorize(traceColor);
			if (traceName != null) {
				traceListModel.addElement(traceName);
			}
		});
	}

	private void setupBtnChooseTraceColor(JButton btnChooseTraceColor) {
		btnChooseTraceColor.setOpaque(true);
		btnChooseTraceColor.setBackground(traceColor);
		btnChooseTraceColor.addActionListener(e -> {
			Color newColor = JColorChooser.showDialog(panel, "Choose a color", traceColor);
			if (newColor != null) {
				traceColor = newColor;
				btnChooseTraceColor.setBackground(traceColor);
			}
		});
	}

	private void setupBtnAddHook(JButton btnAddHook, JComboBox<String> comboBoxHookMode) {
		btnAddHook.addActionListener(e -> {
            String libraryName = ui.textFieldLibrary.getText();
            String functionName = ui.textFieldFunction.getText();
            String entryAddress = ui.textFieldEntry.getText();
            String leaveAddress = ui.textFieldLeave.getText();
            String targetAddress = ui.textFieldTarget.getText();
            String mode = (String) comboBoxHookMode.getSelectedItem();

            Map<Long, List<String>> hook = new HashMap<>();
            List<String> hookDetails = new ArrayList<>(
            		Arrays.asList(libraryName, functionName, entryAddress, leaveAddress, targetAddress, mode)
            	);
            long hookId = TraceFileController.generateHookId();
            hook.put(hookId, hookDetails);
            hookListModel.addElement(hook);
            
            traceFileController.addHook(libraryName, functionName, hookId, entryAddress, leaveAddress, targetAddress, mode);
		});
	}
	
	private void setupBtnRemoveHook(JButton btnRemoveHook) {
		btnRemoveHook.addActionListener(e -> {
			// Remove hook from trace file data structure
			List<Map<Long, List<String>>> selectedItems = hookList.getSelectedValuesList();
			Set<Long> hookIds = new HashSet<>();
			for (Map<Long, List<String>> item : selectedItems) {
				hookIds.addAll(item.keySet());
			}
			for (long hookId : hookIds) {
				traceFileController.removeHook(hookId);
			}
			
			// Remove hook from UI
			int[] selectedIndices = hookList.getSelectedIndices();
			for (int i = selectedIndices.length-1; i >= 0; i--) {
				hookListModel.remove(selectedIndices[i]);
			}
		});
	}

	private void setupBtnAddRegister(JButton btnAddRegister, JCheckBox cbIsSymbolic) {
		btnAddRegister.addActionListener(e -> {
        	String name = ui.textFieldRegisterName.getText();
        	String value = ui.textFieldRegisterValue.getText();
        	boolean isSymbolic = cbIsSymbolic.isSelected();
        	
        	for (int i = 0; i < registerListModel.getSize(); i++) {
        	    List<String> register = registerListModel.getElementAt(i);
        	    if (register.get(0).equals(name)) {
					Msg.showError(this, panel, "Register duplicate", "Register " + name + " already exists");
					return;
        	    }
        	}

            List<String> register = new ArrayList<>(
            		Arrays.asList(name, value)
            	);
            if (isSymbolic) {
            	register.add(traceFileController.getSymbolicMarker());
            }
            registerListModel.addElement(register);
            
            traceFileController.addEntryStateRegister(name, value, isSymbolic);
		});
	}
	
	private void setupBtnRemoveRegister(JButton btnRemoveRegister) {
		btnRemoveRegister.addActionListener(e -> {
			// Remove registers from trace file data structure
			List<List<String>> selectedItems = registerList.getSelectedValuesList();
			Set<String> registerNames = new HashSet<>();
			for (List<String> item : selectedItems) {
				registerNames.add(item.get(0));
			}
			for (String name : registerNames) {
				traceFileController.removeEntryStateRegister(name);
			}
			
			// Remove registers from UI
			int[] selectedIndices = registerList.getSelectedIndices();
			for (int i = selectedIndices.length-1; i >= 0; i--) {
				registerListModel.remove(selectedIndices[i]);
			}
		});
	}

	private void setupBtnAddMemory(JButton btnAddMemory, JCheckBox chckbxIsMemorySymbolic) {
		btnAddMemory.addActionListener(e -> {
        	String address = ui.textFieldMemoryAddress.getText();
        	String value = ui.textFieldMemoryValue.getText();
        	boolean isSymbolic = chckbxIsMemorySymbolic.isSelected();
        	
        	for (int i = 0; i < memoryListModel.getSize(); i++) {
        	    List<String> memory = memoryListModel.getElementAt(i);
        	    if (memory.get(0).equals(address)) {
					Msg.showError(this, panel, "Memory address duplicate", "Memory address " + address + " already exists");
					return;
        	    }
        	}

            List<String> memoryUnit = new ArrayList<>(
            		Arrays.asList(address, value)
            	);
            if (isSymbolic) {
            	memoryUnit.add(traceFileController.getSymbolicMarker());
            }
            memoryListModel.addElement(memoryUnit);
            
            traceFileController.addEntryStateMemory(address, value, isSymbolic);
		});
	}
	
	private void setupBtnRemoveMemory(JButton btnRemoveMemory) {
		btnRemoveMemory.addActionListener(e -> {
			// Remove memory addresses from trace file data structure
			List<List<String>> selectedItems = memoryList.getSelectedValuesList();
			Set<String> memoryAddresses = new HashSet<>();
			for (List<String> item : selectedItems) {
				memoryAddresses.add(item.get(0));
			}
			for (String address : memoryAddresses) {
				traceFileController.removeEntryStateMemory(address);
			}
			
			// Remove memory addresses from UI
			int[] selectedIndices = memoryList.getSelectedIndices();
			for (int i = selectedIndices.length-1; i >= 0; i--) {
				memoryListModel.remove(selectedIndices[i]);
			}
		});
	}
	
	private void setupBtnLoadTraceFile(JButton btnLoadTraceFile) {
		btnLoadTraceFile.addActionListener(e -> {
			clearTraceFile();
		});
	}
	
	private void setupBtnCreateTraceFile(JButton btnCreateTraceFile) {
		btnCreateTraceFile.addActionListener(e -> {
			traceFileController.createTraceFile(panel);
		});
	}
	
	private void setupBtnClearTraceFile(JButton btnClearTraceFile) {
		btnClearTraceFile.addActionListener(e -> {
			clearTraceFile();
		});
	}
	
	private void clearTraceFile() {
		// Clear hooks
		ui.textFieldLibrary.setText("");
		ui.textFieldFunction.setText("");
		ui.textFieldEntry.setDocument(new HexDocument());
		ui.textFieldLeave.setDocument(new HexDocument());
		ui.textFieldTarget.setDocument(new HexDocument());
		hookListModel.clear();
		
		// Clear registers
		ui.textFieldRegisterName.setText("");
		ui.textFieldRegisterValue.setDocument(new HexDocument());
		ui.chckbxIsRegisterSymbolic.setSelected(false);
		registerListModel.clear();
		
		// Clear memory
		ui.textFieldMemoryAddress.setDocument(new HexDocument());
		ui.textFieldMemoryValue.setDocument(new HexDocument());
		ui.chckbxIsMemorySymbolic.setSelected(false);
		memoryListModel.clear();
		
		// Clear data structure
		traceFileController.clearTraceFile();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
