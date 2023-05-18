package model;

import java.util.ArrayList;
import java.util.List;

import util.ObservableSet;

public class MorionTraceFile extends MorionInitTraceFile {
	private final ObservableSet<MemoryEntry> leaveMemory = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> leaveRegisters = new ObservableSet<>();
	private List<List<String>> instructions = new ArrayList<>();
	
	public ObservableSet<MemoryEntry> getLeaveMemory() {
		return leaveMemory;
	}
	
	public ObservableSet<MemoryEntry> getLeaveRegisters() {
		return leaveRegisters;
	}
	
	public List<List<String>> getInstructions() {
		return instructions;
	}
	
	public void setInstructions(List<List<String>> instructions) {
		this.instructions = instructions;
	}

	@Override
	public void clear() {
		super.clear();
		leaveMemory.clear();
		leaveRegisters.clear();
		instructions.clear();
	}
}
