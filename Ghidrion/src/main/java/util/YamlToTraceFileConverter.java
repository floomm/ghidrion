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
		Map<String, List<String>> entryMemoryMap = getEntryStateMap(traceFileToConvert)
				.get(MorionTraceFile.STATE_MEMORY);
		traceFile.getEntryMemory().replaceAll(mapToMemoryEntries(entryMemoryMap));
	}
	
	private static void addEntryRegisters(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, List<String>> entryRegistersMap = getEntryStateMap(traceFileToConvert)
				.get(MorionTraceFile.STATE_REGISTERS);
		traceFile.getEntryRegisters().replaceAll(mapToMemoryEntries(entryRegistersMap));
	}
	
	private static void addLeaveMemory(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, List<String>> leaveMemoryMap = getLeaveStateMap(traceFileToConvert)
				.get(MorionTraceFile.STATE_MEMORY);
		traceFile.getLeaveMemory().replaceAll(mapToMemoryEntries(leaveMemoryMap));
	}
	
	private static void addLeaveRegisters(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, List<String>> leaveRegistersMap = getLeaveStateMap(traceFileToConvert)
				.get(MorionTraceFile.STATE_REGISTERS);
		traceFile.getLeaveRegisters().replaceAll(mapToMemoryEntries(leaveRegistersMap));
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
		return getStatesMap(traceFileToConvert).get(MorionTraceFile.ENTRY_STATE);
	}
	
	private static Map<String, Map<String, List<String>>> getLeaveStateMap(Map<String, Object> traceFileToConvert) {
		return getStatesMap(traceFileToConvert).get(MorionTraceFile.LEAVE_STATE);
	}
	
	private static Map<String, Map<String, Map<String, List<String>>>> getStatesMap(Map<String, Object> traceFileToConvert) {
		return (Map<String, Map<String, Map<String, List<String>>>>) traceFileToConvert.get(MorionTraceFile.STATES);
	}

}
