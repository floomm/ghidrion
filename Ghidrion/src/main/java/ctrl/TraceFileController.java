package ctrl;

import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.yaml.snakeyaml.Yaml;

import ghidra.util.Msg;
import model.Hook;
import model.MorionTraceFile;

public class TraceFileController {

	private MorionTraceFile traceFile = new MorionTraceFile();
	
	public String getSymbolicMarker() {
		return MorionTraceFile.SYMBOLIC;
	}
	
	public void addHook(String libraryName, String functionName, String entryAddress, String leaveAddress, String mode) {
		Hook hook = new Hook(libraryName, functionName, entryAddress, leaveAddress, mode);
		removeHook(hook); // Possibly, hook has to be replaced
		traceFile.addHook(hook);
	}
	
	public void removeHook(String libraryName, String functionName, String entryAddress, String leaveAddress, String mode) {
		Hook hook = new Hook(libraryName, functionName, entryAddress, leaveAddress, mode);
		removeHook(hook);
	}
	
	public void addEntryStateRegister(String name, String value, boolean isSymbolic) {
		List<String> valueList = new ArrayList<>();
		valueList.add(value);
		if (isSymbolic) {
			valueList.add(MorionTraceFile.SYMBOLIC);
		}
		traceFile.addEntryStateRegister(name, valueList);
	}
	
	public void removeEntryStateRegister(String registerName) {
		Map<String, List<String>> entryRegisters = traceFile.getEntryRegisters();
		entryRegisters.remove(registerName);
	}

	public void addEntryStateMemory(String address, String value, boolean isSymbolic) {
		List<String> valueList = new ArrayList<>();
		valueList.add(value);
		if (isSymbolic) {
			valueList.add(MorionTraceFile.SYMBOLIC);
		}
		traceFile.addEntryStateMemory(address, valueList);
	}
	
	public void removeEntryStateMemory(String address) {
		Map<String, List<String>> entryMemory = traceFile.getEntryMemory();
		entryMemory.remove(address);
	}
	
	public void createTraceFile(Component container) {
		Yaml yaml = new Yaml();
		
		Map<String, Object> traceFileDump = new HashMap<>();
		traceFileDump.put("hooks", createHooksDump());
		traceFileDump.put("info", traceFile.getInfo());
		traceFileDump.put("instructions", traceFile.getInstructions());
		traceFileDump.put("states", traceFile.getStates());
		
		String content = yaml.dump(traceFileDump);
		
		JFileChooser fileChooser = new JFileChooser();
		int result = fileChooser.showSaveDialog(container);
		File file = null;
		if (result == JFileChooser.APPROVE_OPTION) {
			file = fileChooser.getSelectedFile();
		}
		
		if (file != null) {
			try (FileOutputStream fos = new FileOutputStream(file)) {
				fos.write(content.getBytes());
				fos.close();
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		}
	}
	
	public void clearTraceFile() {
		traceFile.getHooks().clear();
		traceFile.getInfo().clear();
		traceFile.getInstructions().clear();
		traceFile.setEntryAddress(null);
		traceFile.getEntryMemory().clear();
		traceFile.getEntryRegisters().clear();
		traceFile.setLeaveAddress(null);
		traceFile.getLeaveMemory().clear();
		traceFile.getLeaveRegisters().clear();
	}
	
	private void removeHook(Hook hook) {
		Iterator<Hook> hooksIter = traceFile.getHooks().iterator();
		while (hooksIter.hasNext()) {
			if (hook.equals(hooksIter.next())) {
				hooksIter.remove();
			}
		}
	}
	
	private Map<String, Map<String, List<Map<String, String>>>> createHooksDump() {
		Map<String, Map<String, List<Map<String, String>>>> hooksDump = new HashMap<>();
		
		for (Hook hook : traceFile.getHooks()) {
			Map<String, String> hookDetails = new HashMap<>();
			hookDetails.put("entry", hook.getEntryAddress());
			hookDetails.put("leave", hook.getLeaveAddress());
			hookDetails.put("target", hook.getTargetAddress());
			hookDetails.put("mode", hook.getMode());
			
			hooksDump.computeIfAbsent(hook.getLibraryName(), k -> new HashMap<>())
				.computeIfAbsent(hook.getFunctionName(), k -> new ArrayList<>())
				.add(hookDetails);
		}
		
		return hooksDump;
	}
	
	private File askTraceFile() {
		JFileChooser fileChooser = new JFileChooser();

		// Filter for yaml files
		FileNameExtensionFilter filter = new FileNameExtensionFilter("YAML files", "yaml");
		fileChooser.setFileFilter(filter);

		int returnState = fileChooser.showOpenDialog(null);
		if (returnState == JFileChooser.APPROVE_OPTION) {
			Msg.info(this, "Imported file: " + fileChooser.getSelectedFile().getName());
		}
		
		return fileChooser.getSelectedFile();
	}
}
