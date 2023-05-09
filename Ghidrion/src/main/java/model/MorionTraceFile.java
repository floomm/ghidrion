package model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import util.ObservableSet;

public class MorionTraceFile {
	private final ObservableSet<Hook> hooks = new ObservableSet<>();
	private final Map<String, String> info = new HashMap<>();
	private final List<List<String>> instructions = new ArrayList<>();
	private final Map<String, Object> states = new HashMap<>();
	private final ObservableSet<MemoryEntry> entryMemory = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> entryRegisters = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> leaveMemory = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> leaveRegisters = new ObservableSet<>();

	public Map<String, String> getInfo() {
		return this.info;
	}

	public List<List<String>> getInstructions() {
		return this.instructions;
	}

	public Map<String, Object> getStates() {
		return this.states;
	}

	public Set<MemoryEntry> getEntryMemory() {
		return this.entryMemory.getSet();
	}

	public void addEntryStateMemory(MemoryEntry m) {
		this.entryMemory.add(m);
	}

	public void removeEntryMemoryEntries(Collection<MemoryEntry> memoryEntries) {
		this.entryMemory.removeAll(memoryEntries);
	}

	public ObservableSet<MemoryEntry> getEntryMemoryObservable() {
		return this.entryMemory;
	}

	public Set<MemoryEntry> getEntryRegisters() {
		return this.entryRegisters.getSet();
	}

	public void addEntryStateRegister(MemoryEntry register) {
		this.entryRegisters.add(register);
	}

	public void removeEntryRegisters(Collection<MemoryEntry> registers) {
		this.entryRegisters.removeAll(registers);
	}

	public ObservableSet<MemoryEntry> getEntryRegistersObservable() {
		return this.entryRegisters;
	}

	public Set<MemoryEntry> getLeaveMemory() {
		return this.leaveMemory.getSet();
	}

	public Set<MemoryEntry> getLeaveRegisters() {
		return this.leaveRegisters.getSet();
	}

	public Set<Hook> getHooks() {
		return this.hooks.getSet();
	}

	public void addHooks(Collection<Hook> hook) {
		this.hooks.addAll(hook);
	}

	public void removeHooks(Collection<Hook> hooks) {
		this.hooks.removeAll(hooks);
	}

	public ObservableSet<Hook> getHookObservable() {
		return this.hooks;
	}

	public void clear() {
		this.hooks.clear();
		this.info.clear();
		this.instructions.clear();
		this.entryMemory.clear();
		this.entryRegisters.clear();
		this.leaveMemory.clear();
		this.leaveRegisters.clear();
	}
}
