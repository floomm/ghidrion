package model;

import ghidra.program.model.address.Address;
import util.ObservableSet;

/**
 * Represents a Morion trace file.
 * It extends the {@link MorionInitTraceFile} class and adds observable sets of leave memory entries, leave register entries,
 * and traced instructions. It also tracks the entry and leave addresses of the Morion trace.
 */
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

	/**
     * Clears the trace file by removing all hooks, entry memory entries, entry register entries, leave memory entries,
     * leave register entries, traced instructions, and resetting the entry and leave addresses.
     */
	@Override
	public void clear() {
		super.clear();
		leaveMemory.clear();
		leaveRegisters.clear();
		instructions.clear();
		entryAddress = null;
		leaveAddress = null;
	}
}
