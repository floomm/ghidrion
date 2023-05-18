package model;

import util.ObservableSet;

public class MorionTraceFile extends MorionInitTraceFile {
	private final ObservableSet<MemoryEntry> leaveMemory = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> leaveRegisters = new ObservableSet<>();
	
	public ObservableSet<MemoryEntry> getLeaveMemory() {
		return leaveMemory;
	}
	
	public ObservableSet<MemoryEntry> getLeaveRegisters() {
		return leaveRegisters;
	}

	@Override
	public void clear() {
		super.clear();
		leaveMemory.clear();
		leaveRegisters.clear();
	}
}
