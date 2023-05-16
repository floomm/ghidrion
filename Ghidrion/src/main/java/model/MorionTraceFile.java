package model;

import util.ObservableSet;

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
	
	private final ObservableSet<Hook> hooks = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> entryMemory = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> entryRegisters = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> leaveMemory = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> leaveRegisters = new ObservableSet<>();

	public ObservableSet<MemoryEntry> getEntryMemory() {
		return entryMemory;
	}

	public ObservableSet<MemoryEntry> getEntryRegisters() {
		return entryRegisters;
	}
	
	public ObservableSet<MemoryEntry> getLeaveMemory() {
		return leaveMemory;
	}
	
	public ObservableSet<MemoryEntry> getLeaveRegisters() {
		return leaveRegisters;
	}

	public ObservableSet<Hook> getHooks() {
		return hooks;
	}
	
	public void clear() {
		hooks.clear();
		entryMemory.clear();
		entryRegisters.clear();
		leaveMemory.clear();
		leaveRegisters.clear();
	}
}
