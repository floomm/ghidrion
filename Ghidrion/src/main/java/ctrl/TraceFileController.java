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

import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ghidrion.GhidrionPlugin;
import model.Hook;
import model.Hook.Mode;
import model.MorionTraceFile;

public class TraceFileController {

	private MorionTraceFile traceFile = new MorionTraceFile();
	private GhidrionPlugin plugin;
	
	public TraceFileController(GhidrionPlugin plugin) {
		this.plugin = plugin;
	}
	
	public String getSymbolicMarker() {
		return MorionTraceFile.SYMBOLIC;
	}
	
	public void addHook(String libraryName, String functionName, String entry, String leave, String mode) {
		Address entryAddress = plugin.getFlatAPI().toAddr(entry);
		Address leaveAddress = plugin.getFlatAPI().toAddr(leave);
		Hook hook = new Hook(libraryName, functionName, entryAddress, leaveAddress, Mode.fromValue(mode));
		removeHook(hook); // Possibly, hook has to be replaced
		traceFile.addHook(hook);
	}
	
	public void removeHook(String libraryName, String functionName, String entry, String leave, String mode) {
		Address entryAddress = plugin.getFlatAPI().toAddr(entry);
		Address leaveAddress = plugin.getFlatAPI().toAddr(leave);
		Hook hook = new Hook(libraryName, functionName, entryAddress, leaveAddress, Mode.fromValue(mode));
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
	
	public void createTraceFile(Component parent) {
		Yaml yaml = new Yaml();
		
		
		String content = yaml.dump(buildTraceFileDump());
		
		JFileChooser fileChooser = new JFileChooser();
		int result = fileChooser.showSaveDialog(parent);
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
	
	private Map<String, Object> buildTraceFileDump() {
		Map<String, Object> traceFileDump = new HashMap<>();
		traceFileDump.put(MorionTraceFile.HOOKS, buildHooksDump());
		traceFileDump.put(MorionTraceFile.INFO, traceFile.getInfo());
		traceFileDump.put(MorionTraceFile.INSTRUCTIONS, traceFile.getInstructions());
		traceFileDump.put(MorionTraceFile.STATES, traceFile.getStates());
		return traceFileDump;
	}
	
	private Map<String, Map<String, List<Map<String, String>>>> buildHooksDump() {
		Map<String, Map<String, List<Map<String, String>>>> hooksDump = new HashMap<>();
		
		for (Hook hook : traceFile.getHooks()) {
			Map<String, String> hookDetails = new HashMap<>();
			hookDetails.put(MorionTraceFile.HOOK_ENTRY, "0x" + hook.getEntryAddress().toString());
			hookDetails.put(MorionTraceFile.HOOK_LEAVE, "0x" + hook.getLeaveAddress().toString());
			hookDetails.put(MorionTraceFile.HOOK_TARGET, hook.getTargetAddress());
			hookDetails.put(MorionTraceFile.HOOK_MODE, hook.getMode().getValue());
			
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
