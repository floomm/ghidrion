package ctrl;

import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.yaml.snakeyaml.Yaml;

import ghidra.util.Msg;
import model.MorionTraceFile;

public class TraceFileController {

	private MorionTraceFile traceFile = new MorionTraceFile();
	private Map<Long, Map<String, String>> hookDetailsMap = new HashMap<>();
	
	private static long hookCounter = 0;
	
	public String getSymbolicMarker() {
		return MorionTraceFile.SYMBOLIC;
	}
	
	public void addHook(String libraryName, String functionName, long hookId, String entry, String leave, String target, String mode) {
		Map<String, String> hookDetails = new HashMap<>();
		hookDetails.put("entry", entry);
		hookDetails.put("leave", leave);
		hookDetails.put("target", target);
		hookDetails.put("mode", mode);
		
		traceFile.addHook(libraryName, functionName, hookDetails);
		hookDetailsMap.put(hookId, hookDetails);
	}
	
	public void removeHook(long hookId) {
		Map<String, String> hookDetails = hookDetailsMap.get(hookId);
		
		// lib, function, hookdetails
		Map<String, Map<String, List<Map<String, String>>>> hooks = traceFile.getHooks();
		var hooksIter = hooks.entrySet().iterator();
		while(hooksIter.hasNext()) {
			var library = hooksIter.next();
			var libraryIter = library.getValue().entrySet().iterator();
			while (libraryIter.hasNext()) {
				var function = libraryIter.next();
				var functionIter = function.getValue().iterator();
				while (functionIter.hasNext()) {
					var functionDetails = functionIter.next();
					if (functionDetails == hookDetails) {
						String entry = functionDetails.get("entry");
						String leave = functionDetails.get("leave");
						String target = functionDetails.get("target");
						String mode = functionDetails.get("mode");
						String message = String.format("Removed hook {id=%d, lib=%s, func=%s, entry=%s, leave=%s, target=%s, mode=%s}", hookId, library.getKey(), function.getKey(), entry, leave, target, mode);
						Msg.info(this, message);
						functionIter.remove();
					}
				}
				if (function.getValue().isEmpty()) {
					String message = String.format("Removed function {lib=%s, func=%s}", library.getKey(), function.getKey());
					Msg.info(this, message);
					libraryIter.remove();
				}
			}
			if (library.getValue().isEmpty()) {
				String message = String.format("Removed library %s", library.getKey());
				Msg.info(this, message);
				hooksIter.remove();
			}
		}
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
		String content = yaml.dump(traceFile.getTraceFile());
		
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
	
	public static synchronized long generateHookId() {
		return hookCounter++;
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
