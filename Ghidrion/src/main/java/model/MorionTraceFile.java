package model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MorionTraceFile {
	
	public static final String HOOKS = "hooks";
	public static final String HOOK_ENTRY = "entry";
	public static final String HOOK_LEAVE = "leave";
	public static final String HOOK_TARGET = "target";
	public static final String HOOK_MODE = "mode";
	public static final String INFO = "info";
	public static final String INSTRUCTIONS = "instructions";
	public static final String STATES = "states";
	public static final String ENTRY_STATE = "entry";
	public static final String LEAVE_STATE = "leave";
	public static final String STATE_ADDRESS = "addr";
	public static final String STATE_MEMORY = "mems";
	public static final String STATE_REGISTERS = "regs";
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
		states.put(ENTRY_STATE, entryState);
		entryState.put(STATE_ADDRESS, entryAddress);
		entryState.put(STATE_MEMORY, entryMemory);
		entryState.put(STATE_REGISTERS, entryRegisters);
		states.put(LEAVE_STATE, leaveState);
		leaveState.put(STATE_ADDRESS, leaveAddress);
		leaveState.put(STATE_MEMORY, leaveMemory);
		leaveState.put(STATE_REGISTERS, leaveRegisters);
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
