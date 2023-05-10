package model;

import java.util.Collection;
import java.util.Set;
import util.ObservableSet;

public class MorionTraceFile {
	private final ObservableSet<Hook> hooks = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> entryMemory = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> entryRegisters = new ObservableSet<>();

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
		this.entryMemory.clear();
		this.entryRegisters.clear();
	}
}
