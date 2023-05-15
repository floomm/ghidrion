package util;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.yaml.snakeyaml.Yaml;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import model.Hook;
import model.Hook.Mode;
import model.MemoryEntry;
import model.MorionTraceFile;

public class YamlToTraceFileConverter {
	
	public static void toTraceFile(MorionTraceFile traceFile, InputStream yamlStream, AddressFactory addressFactory) {
		Map<String, Object> traceFileToConvert = new Yaml().load(yamlStream);
		
		addHooks(traceFile, traceFileToConvert, addressFactory);
		addEntryMemory(traceFile, traceFileToConvert);
		addEntryRegisters(traceFile, traceFileToConvert);
		addLeaveMemory(traceFile, traceFileToConvert);
		addLeaveRegisters(traceFile, traceFileToConvert);
	}
	
	private static void addHooks(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert, AddressFactory addressFactory) {
		Map<String, Map<String, List<Map<String, String>>>> hookMap = (Map<String, Map<String, List<Map<String, String>>>>) traceFileToConvert
				.get(MorionTraceFile.HOOKS);
		traceFile.getHooks().replaceAll(mapToHooks(hookMap, addressFactory));
	}
	
	private static Set<Hook> mapToHooks(Map<String, Map<String, List<Map<String, String>>>> hookMap, AddressFactory addressFactory) {
		Set<Hook> hooks = new HashSet<>();
		Map<String, List<Map<String, String>>> functions = hookMap.get("libc"); // Libc is hardcoded for now
		for (String functionName : functions.keySet()) {
			for (Map<String, String> hookDetails : functions.get(functionName)) {
				String entry = hookDetails.get(MorionTraceFile.HOOK_ENTRY);
				Address entryAddress = addressFactory.getAddress(entry);
				Mode mode = Mode.fromValue(hookDetails.get(MorionTraceFile.HOOK_MODE));
				hooks.add(new Hook(functionName, entryAddress, mode));
			}
		}
		return hooks;
	}
	
	private static void addEntryMemory(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, List<String>>> entryStateMap = getEntryStateMap(traceFileToConvert);
		if (entryStateMap != null && entryStateMap.containsKey(MorionTraceFile.STATE_MEMORY)) {
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(entryStateMap.get(MorionTraceFile.STATE_MEMORY));
			traceFile.getEntryMemory().replaceAll(memoryEntries);
		}
	}
	
	private static void addEntryRegisters(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, List<String>>> entryStateMap = getEntryStateMap(traceFileToConvert);
		if (entryStateMap != null && entryStateMap.containsKey(MorionTraceFile.STATE_REGISTERS)) {
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(entryStateMap.get(MorionTraceFile.STATE_REGISTERS));
			traceFile.getEntryRegisters().replaceAll(memoryEntries);
		}
	}
	
	private static void addLeaveMemory(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, List<String>>> leaveStateMap = getLeaveStateMap(traceFileToConvert);
		if (leaveStateMap != null && leaveStateMap.containsKey(MorionTraceFile.STATE_MEMORY)) {
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(leaveStateMap.get(MorionTraceFile.STATE_MEMORY));
			traceFile.getLeaveMemory().replaceAll(memoryEntries);
		}
	}
	
	private static void addLeaveRegisters(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, List<String>>> leaveStateMap = getLeaveStateMap(traceFileToConvert);
		if (leaveStateMap != null && leaveStateMap.containsKey(MorionTraceFile.STATE_REGISTERS)) {
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(leaveStateMap.get(MorionTraceFile.STATE_REGISTERS));
			traceFile.getLeaveRegisters().replaceAll(memoryEntries);
		}
	}

	private static List<MemoryEntry> mapToMemoryEntries(Map<String, List<String>> entryMap) {
		List<MemoryEntry> entries = new ArrayList<>();
		for (String name : entryMap.keySet()) {
			String value = entryMap.get(name).get(0);
			boolean symbolic = (entryMap.get(name).size() > 1);
			entries.add(new MemoryEntry(name, value, symbolic));
		}
		return entries;
	}
	
	private static Map<String, Map<String, List<String>>> getEntryStateMap(Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, List<String>>> entryStateMap = null;
		Map<String, Map<String, Map<String, List<String>>>> statesMap = getStatesMap(traceFileToConvert);
		if (statesMap != null && statesMap.containsKey(MorionTraceFile.ENTRY_STATE)) {
			entryStateMap = statesMap.get(MorionTraceFile.ENTRY_STATE);
		}
		return entryStateMap;
	}
	
	private static Map<String, Map<String, List<String>>> getLeaveStateMap(Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, List<String>>> leaveStateMap = null;
		Map<String, Map<String, Map<String, List<String>>>> statesMap = getStatesMap(traceFileToConvert);
		if (statesMap != null && statesMap.containsKey(MorionTraceFile.LEAVE_STATE)) {
			leaveStateMap = statesMap.get(MorionTraceFile.LEAVE_STATE);
		}
		return leaveStateMap;
	}
	
	private static Map<String, Map<String, Map<String, List<String>>>> getStatesMap(Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, Map<String, List<String>>>> statesMap = null;
		if (traceFileToConvert.containsKey(MorionTraceFile.STATES)) {
			statesMap = (Map<String, Map<String, Map<String, List<String>>>>) traceFileToConvert.get(MorionTraceFile.STATES);
		}
		return statesMap;
	}

}
