package model;

import util.ObservableSet;

/**
 * Represents a Morion init trace file.
 * It maintains observable sets of hooks, entry memory entries, and entry register entries.
 */
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
	
	/**
     * Clears the initialization trace file by removing all hooks, entry memory entries, and entry register entries.
     */
	public void clear() {
		hooks.clear();
		entryMemory.clear();
		entryRegisters.clear();
	}
}
