package model;

import util.ObservableSet;

public class MorionInitTraceFile {
	private final ObservableSet<Hook> hooks = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> entryMemory = new ObservableSet<>();
	private final ObservableSet<MemoryEntry> entryRegisters = new ObservableSet<>();

	public ObservableSet<MemoryEntry> getEntryMemory() {
		return entryMemory;
	}

	public ObservableSet<MemoryEntry> getEntryRegisters() {
		return entryRegisters;
	}

	public ObservableSet<Hook> getHooks() {
		return hooks;
	}
	
	public void clear() {
		hooks.clear();
		entryMemory.clear();
		entryRegisters.clear();
	}
}
