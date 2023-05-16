package util;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.parser.ParserException;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.util.Msg;
import model.Hook;
import model.Hook.Mode;
import model.MemoryEntry;
import model.MorionTraceFile;
import view.HexDocument;

public class YamlToTraceFileConverter {
	
	public static void toInitTraceFile(MorionTraceFile traceFile, InputStream yamlStream, AddressFactory addressFactory) {
		Map<String, Object> traceFileToConvert = loadTraceFile(yamlStream);
		if (traceFileToConvert == null) {
			return;
		}
		
		addHooks(traceFile, traceFileToConvert, addressFactory);
		addEntryMemory(traceFile, traceFileToConvert);
		addEntryRegisters(traceFile, traceFileToConvert);
	}
	
	public static void toTraceFile(MorionTraceFile traceFile, InputStream yamlStream, AddressFactory addressFactory) {
		Map<String, Object> traceFileToConvert = loadTraceFile(yamlStream);
		if (traceFileToConvert == null) {
			return;
		}
		
		addHooks(traceFile, traceFileToConvert, addressFactory);
		addEntryMemory(traceFile, traceFileToConvert);
		addEntryRegisters(traceFile, traceFileToConvert);
		addLeaveMemory(traceFile, traceFileToConvert);
		addLeaveRegisters(traceFile, traceFileToConvert);
	}
	
	private static Map<String, Object> loadTraceFile(InputStream yamlStream) {
		Map<String, Object> traceFileToConvert = null;
		try {
			traceFileToConvert = new Yaml().load(yamlStream);
		} catch (ParserException e) {
			Msg.showError(YamlToTraceFileConverter.class, null, "Parser exception", e.getMessage(), e);
		}
		return traceFileToConvert;
	}
	
	private static void addHooks(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert, AddressFactory addressFactory) {
		Map<String, Map<String, List<Map<String, String>>>> hookMap = (Map<String, Map<String, List<Map<String, String>>>>) traceFileToConvert
				.get(MorionTraceFile.HOOKS);
		Set<Hook> hooks = mapToHooks(hookMap, addressFactory);
		if (hooks == null) {
			return;
		}
		traceFile.getHooks().replaceAll(hooks);
	}
	
	private static Set<Hook> mapToHooks(Map<String, Map<String, List<Map<String, String>>>> hookMap, AddressFactory addressFactory) {
		Set<Hook> hooks = new HashSet<>();
		Map<String, List<Map<String, String>>> functions = hookMap.get("libc"); // Libc is hardcoded for now
		for (String functionName : functions.keySet()) {
			for (Map<String, String> hookDetails : functions.get(functionName)) {
				Address entry = getHookEntryAddress(functionName, hookDetails, addressFactory);
				Mode mode = getHookMode(functionName, hookDetails, entry);
				if (entry == null || mode == null) {
					return null;
				}

				try {
					hooks.add(new Hook(functionName, entry, mode));
				} catch (NullPointerException e) {
					String message = "Hook entry address " + entry + " is illegal"
							+ " (Function: " + functionName + ")";
					Msg.showError(YamlToTraceFileConverter.class, null, "Illegal hook entry", message, e);
					return null;
				}
			}
		}
		return hooks;
	}
	
	private static Address getHookEntryAddress(String functionName, Map<String, String> hookDetails, AddressFactory addressFactory) {
		if (! (hookDetails.containsKey(MorionTraceFile.HOOK_ENTRY))) {
			String message = "Hook entry address is missing (Function: " + functionName + ")";
			Msg.showError(YamlToTraceFileConverter.class, null, "Entry missing", message);
			return null;
		}
		String entry = hookDetails.get(MorionTraceFile.HOOK_ENTRY);
		return addressFactory.getAddress(entry);
	}
	
	private static Mode getHookMode(String functionName, Map<String, String> hookDetails, Address entry) {
		if (! (hookDetails.containsKey(MorionTraceFile.HOOK_MODE))) {
			String message = "Hook mode is missing (Function: " + functionName + ", Entry: " + entry + ")";
			Msg.showError(YamlToTraceFileConverter.class, null, "Mode missing", message);
			return null;
		}
		Mode mode = null;
		try {
			mode = Mode.fromValue(hookDetails.get(MorionTraceFile.HOOK_MODE));
		} catch (IllegalArgumentException e) {
			String message = "Hook mode " + hookDetails.get(MorionTraceFile.HOOK_MODE) + " is illegal" 
					+ " (Function: " + functionName + ", Entry: " + entry + ")";
			Msg.showError(YamlToTraceFileConverter.class, null, "Illegal hook mode", message, e);
		}
		return mode;
	}
	
	private static void addEntryMemory(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, List<String>>> entryStateMap = getEntryStateMap(traceFileToConvert);
		if (entryStateMap != null && entryStateMap.containsKey(MorionTraceFile.STATE_MEMORY)) {
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(entryStateMap.get(MorionTraceFile.STATE_MEMORY));
			if (memoryEntries != null && hasValidMemoryStateAddresses(memoryEntries)) {
				traceFile.getEntryMemory().replaceAll(memoryEntries);
			}
		}
	}
	
	private static void addEntryRegisters(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, List<String>>> entryStateMap = getEntryStateMap(traceFileToConvert);
		if (entryStateMap != null && entryStateMap.containsKey(MorionTraceFile.STATE_REGISTERS)) {
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(entryStateMap.get(MorionTraceFile.STATE_REGISTERS));
			if (memoryEntries != null) {
				traceFile.getEntryRegisters().replaceAll(memoryEntries);
			}
		}
	}
	
	private static void addLeaveMemory(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, List<String>>> leaveStateMap = getLeaveStateMap(traceFileToConvert);
		if (leaveStateMap != null && leaveStateMap.containsKey(MorionTraceFile.STATE_MEMORY)) {
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(leaveStateMap.get(MorionTraceFile.STATE_MEMORY));
			if (memoryEntries != null && hasValidMemoryStateAddresses(memoryEntries)) {
				traceFile.getLeaveMemory().replaceAll(memoryEntries);
			}
		}
	}
	
	private static void addLeaveRegisters(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, List<String>>> leaveStateMap = getLeaveStateMap(traceFileToConvert);
		if (leaveStateMap != null && leaveStateMap.containsKey(MorionTraceFile.STATE_REGISTERS)) {
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(leaveStateMap.get(MorionTraceFile.STATE_REGISTERS));
			if (memoryEntries != null) {
				traceFile.getLeaveRegisters().replaceAll(memoryEntries);
			}
		}
	}
	
	private static boolean hasValidMemoryStateAddresses(List<MemoryEntry> memoryEntries) {
		boolean hasValidMemoryStateAddresses = true;
		for (MemoryEntry entry : memoryEntries) {
			if (! HexDocument.isValidHex(entry.getName())) {
				String message = "Memory state address '" + entry.getName() + "' has to be hexadecimal";
				Msg.showError(YamlToTraceFileConverter.class, null, "Illegal memory state address", message);
				hasValidMemoryStateAddresses = false;
			}
		}
		return hasValidMemoryStateAddresses;
	}

	private static List<MemoryEntry> mapToMemoryEntries(Map<String, List<String>> entryMap) {
		List<MemoryEntry> entries = new ArrayList<>();
		for (String name : entryMap.keySet()) {
			List<String> details = entryMap.get(name);
			if (details == null || details.size() <= 0) {
				String message = "State " + name + " has no value";
				Msg.showError(YamlToTraceFileConverter.class, null, "Missing state value", message);
				return null;
			}
			String value = details.get(0);
			if (! HexDocument.isValidHex(value)) {
				String message = "State " + name + "'s value has to be hexadecimal";
				Msg.showError(YamlToTraceFileConverter.class, null, "Illegal state value", message);
				return null;
			}
			boolean symbolic = details.size() > 1 
					&& MorionTraceFile.SYMBOLIC.equals(details.get(1));
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
