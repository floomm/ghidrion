package model;

import ghidra.program.model.address.Address;
import util.ObservableSet;

public class MorionTraceFile extends MorionInitTraceFile {
	private final ObservableSet<MemoryEntry> leaveMemory = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> leaveRegisters = new ObservableSet<>();
	private final ObservableSet<Instruction> instructions = new ObservableSet<>();
	private Address entryAddress;
	private Address leaveAddress;
	
	public ObservableSet<MemoryEntry> getLeaveMemory() {
		return leaveMemory;
	}
	
	public ObservableSet<MemoryEntry> getLeaveRegisters() {
		return leaveRegisters;
	}
	
	public ObservableSet<Instruction> getInstructions() {
		return instructions;
	}
	
	public Address getEntryAddress() {
		return entryAddress;
	}
	
	public Address getLeaveAddress() {
		return leaveAddress;
	}
	
	public void setEntryAddress(Address entryAddress) {
		this.entryAddress = entryAddress;
	}
	
	public void setLeaveAddress(Address leaveAddress) {
		this.leaveAddress = leaveAddress;
	}

	@Override
	public void clear() {
		super.clear();
		leaveMemory.clear();
		leaveRegisters.clear();
		instructions.clear();
	}
}
