package model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MorionTraceFile {
	
	public static final String SYMBOLIC = "$$";

	private List<Hook> hooks = new ArrayList<>();
	private Map<String, String> info = new HashMap<>();
	private List<List<String>> instructions = new ArrayList<>();
	private Map<String, Object> states = new HashMap<>();
	private Map<String, Object> entryState = new HashMap<>();
	private String entryAddress;
	private Map<String, List<String>> entryMemory = new HashMap<>();
	private Map<String, List<String>> entryRegisters = new HashMap<>();
	private Map<String, Object> leaveState = new HashMap<>();
	private String leaveAddress;
	private Map<String, List<String>> leaveMemory = new HashMap<>();
	private Map<String, List<String>> leaveRegisters = new HashMap<>();
	
	public MorionTraceFile() {
		states.put("entry", entryState);
		entryState.put("addr", entryAddress);
		entryState.put("mems", entryMemory);
		entryState.put("regs", entryRegisters);
		states.put("leave", leaveState);
		leaveState.put("addr", leaveAddress);
		leaveState.put("mems", leaveMemory);
		leaveState.put("regs", leaveRegisters);
	}
	
	public List<Hook> getHooks() {
		return hooks;
	}
	
	public Map<String, String> getInfo() {
		return info;
	}
	
	public List<List<String>> getInstructions() {
		return instructions;
	}
	
	public Map<String, Object> getStates() {
		return states;
	}
	
	public Map<String, List<String>> getEntryMemory() {
		return entryMemory;
	}
	
	public Map<String, List<String>> getEntryRegisters() {
		return entryRegisters;
	}
	
	public Map<String, List<String>> getLeaveMemory() {
		return leaveMemory;
	}
	
	public Map<String, List<String>> getLeaveRegisters() {
		return leaveRegisters;
	}
	
	public void setEntryAddress(String entryAddress) {
		this.entryAddress = entryAddress;
	}
	
	public void setLeaveAddress(String leaveAddress) {
		this.leaveAddress = leaveAddress;
	}
	
	public void addHook(Hook hook) {
		hooks.add(hook);
	}
	
	public void addEntryStateRegister(String name, List<String> valueList) {
		entryRegisters.put(name, valueList);
	}
	
	public void addEntryStateMemory(String address, List<String> valueList) {
		entryMemory.put(address, valueList);
	}

}
