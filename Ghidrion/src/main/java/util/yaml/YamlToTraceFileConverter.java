package util.yaml;

import static util.yaml.ConversionConstants.*;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.parser.ParserException;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import model.Hook;
import model.Hook.Mode;
import model.Instruction;
import model.MemoryEntry;
import model.MorionInitTraceFile;
import model.MorionTraceFile;

public class YamlToTraceFileConverter {

	private static final String HEX_REGEX = "[0-9a-fA-F]+";
	private static final int ONE_BYTE_LENGTH = 4; // maximum length of 0x followed by 2 hexadecimal digits
	private static final int FOUR_BYTE_LENGTH = 10; // maximum length of 0x followed by 8 hexadecimal digits

	/**
	 * Convert the information in the @param yamlStream to a
	 * {@link MorionInitTraceFile}.
	 * This method only converts information needed for a init trace file:
	 * <ul>
	 * <li>Hooks</li>
	 * <li>Entry state memory</li>
	 * <li>Entry state registers</li>
	 * </ul>
	 * 
	 * @param traceFile      {@link MorionInitTraceFile} to write to
	 * @param yamlStream     to write to @param traceFile
	 * @param addressFactory to create {@link Address} objects
	 * @throws YamlConverterException if any exception occurs while converting
	 */
	public static void toInitTraceFile(MorionInitTraceFile traceFile, InputStream yamlStream,
			AddressFactory addressFactory) throws YamlConverterException {
		Map<String, Object> traceFileToConvert = loadTraceFile(traceFile, yamlStream);

		addHooks(traceFile, traceFileToConvert, addressFactory);
		addEntryMemory(traceFile, traceFileToConvert);
		addEntryRegisters(traceFile, traceFileToConvert);
	}

	/**
	 * Convert the information in the @param yamlStream to a
	 * {@link MorionTraceFile}.
	 * This method converts:
	 * <ul>
	 * <li>Hooks</li>
	 * <li>Instructions</li>
	 * <li>Entry state memory</li>
	 * <li>Entry state registers</li>
	 * <li>Leave state memory</li>
	 * <li>Leave state registers</li>
	 * </ul>
	 * 
	 * @param traceFile      {@link MorionTraceFile} to write to
	 * @param yamlStream     to write to @param traceFile
	 * @param addressFactory to create {@link Address} objects
	 * @throws YamlConverterException if any exception occurs while converting
	 */
	public static void toTraceFile(MorionTraceFile traceFile, InputStream yamlStream, AddressFactory addressFactory)
			throws YamlConverterException {
		Map<String, Object> traceFileToConvert = loadTraceFile(traceFile, yamlStream);

		addHooks(traceFile, traceFileToConvert, addressFactory);
		addInstructions(traceFile, traceFileToConvert, addressFactory);
		addEntryAddress(traceFile, traceFileToConvert, addressFactory);
		addEntryMemory(traceFile, traceFileToConvert);
		addEntryRegisters(traceFile, traceFileToConvert);
		addLeaveAddress(traceFile, traceFileToConvert, addressFactory);
		addLeaveMemory(traceFile, traceFileToConvert);
		addLeaveRegisters(traceFile, traceFileToConvert);
	}

	private static Map<String, Object> loadTraceFile(MorionInitTraceFile oldTraceFile, InputStream yamlStream)
			throws YamlConverterException {
		oldTraceFile.clear();
		try {
			Map<String, Object> newTraceFile = new Yaml().load(yamlStream);
			if (newTraceFile == null) {
				throw new YamlConverterException("Empty file", "The loaded trace file is empty");
			}
			return newTraceFile;
		} catch (ParserException e) {
			throw new YamlConverterException("Parser exception", e.getMessage(), e);
		}
	}

	private static void addHooks(MorionInitTraceFile traceFile, Map<String, Object> traceFileToConvert,
			AddressFactory addressFactory) throws YamlConverterException {
		if (traceFileToConvert.containsKey(HOOKS)) {
			Map<String, Map<String, List<Map<String, String>>>> hookMap = (Map<String, Map<String, List<Map<String, String>>>>) traceFileToConvert
					.get(HOOKS);
			Set<Hook> hooks = mapToHooks(hookMap, addressFactory);
			traceFile.getHooks().updateAll(hooks);
		}
	}

	private static Set<Hook> mapToHooks(Map<String, Map<String, List<Map<String, String>>>> hookMap,
			AddressFactory addressFactory) throws YamlConverterException {
		if (hookMap == null)
			return new HashSet<>(); // No libraries -> no hooks

		Set<Hook> hooks = new HashSet<>();
		for (String libName : hookMap.keySet()) {
			Map<String, List<Map<String, String>>> functions = hookMap.get(libName);
			if (functions == null)
				continue; // Ignore empty libraries
			for (String functionName : functions.keySet()) {
				if (functions.get(functionName) == null)
					continue; // Ignore empty functions
				for (Map<String, String> hookDetails : functions.get(functionName)) {
					Address entry = getHookEntryAddress(functionName, hookDetails, addressFactory);
					Mode mode = getHookMode(functionName, hookDetails, entry);
					hooks.add(new Hook(functionName, entry, mode));
				}
			}
		}
		return hooks;
	}

	private static Address getHookEntryAddress(String functionName, Map<String, String> hookDetails,
			AddressFactory addressFactory) throws YamlConverterException {
		if (!(hookDetails.containsKey(HOOK_ENTRY))) {
			String message = "Hook entry address is missing (Function: " + functionName + ")";
			throw new YamlConverterException("Entry missing", message);
		}
		String entry = hookDetails.get(HOOK_ENTRY);
		Address addr = addressFactory.getAddress(entry);
		if ((addr == null) || (!isValidHex(entry, FOUR_BYTE_LENGTH))) {
			String title = "Illegal hook entry";
			String message = "Hook entry address '" + entry + "' is illegal"
					+ " (Function: " + functionName + ")";
			throw new YamlConverterException(title, message);
		}
		return addr;
	}

	private static Mode getHookMode(String functionName, Map<String, String> hookDetails, Address entry)
			throws YamlConverterException {
		if (!(hookDetails.containsKey(HOOK_MODE))) {
			String message = "Hook mode is missing (Function: " + functionName + ", Entry: " + entry + ")";
			throw new YamlConverterException("Mode missing", message);
		}

		Optional<Mode> mode = Mode.fromValue(hookDetails.get(HOOK_MODE));
		if (mode.isEmpty()) {
			String message = "Hook mode '" + hookDetails.get(HOOK_MODE) + "' is illegal"
					+ " (Function: " + functionName + ", Entry: " + entry + ")";
			throw new YamlConverterException("Illegal hook mode", message);
		}

		return mode.get();
	}

	private static void addInstructions(
			MorionTraceFile traceFile,
			Map<String, Object> traceFileToConvert,
			AddressFactory addressFactory) throws YamlConverterException {
		if (!(traceFileToConvert.containsKey(INSTRUCTIONS))) {
			throw new YamlConverterException("No instructions section", "Instructions section is missing");
		}

		Set<Instruction> instructions = new HashSet<>();
		List<List<String>> instructionList = (List<List<String>>) traceFileToConvert.get(INSTRUCTIONS);
		if (instructionList == null) {
			throw new YamlConverterException("No instructions", "The instructions section is empty");
		}
		for (List<String> instruction : instructionList) {
			if ((instruction.size() < 4) || (!isValidHex(instruction.get(0), FOUR_BYTE_LENGTH))) {
				throw new YamlConverterException("Invalid instruction", "An instruction is invalid");
			}
			Address address = addressFactory.getAddress(instruction.get(0));
			String machineCode = instruction.get(1);
			String assemblyCode = instruction.get(2);
			String code = instruction.get(3);
			instructions.add(new Instruction(address, machineCode, assemblyCode, code));
		}
		traceFile.getInstructions().replaceContent(instructions);
	}

	private static void addEntryAddress(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert,
			AddressFactory addressFactory) {
		Map<String, Object> entryStateMap = getEntryStateMap(traceFileToConvert);
		if (entryStateMap.containsKey(STATE_ADDRESS)) {
			String address = (String) entryStateMap.get(STATE_ADDRESS);
			if (address != null) {
				traceFile.setEntryAddress(addressFactory.getAddress(address));
			}
		}
	}

	private static void addEntryMemory(MorionInitTraceFile traceFile, Map<String, Object> traceFileToConvert)
			throws YamlConverterException {
		Map<String, Object> entryStateMap = getEntryStateMap(traceFileToConvert);
		if (entryStateMap.containsKey(STATE_MEMORY)) {
			Map<String, List<String>> entryMap = (Map<String, List<String>>) entryStateMap.get(STATE_MEMORY);
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(entryMap, ONE_BYTE_LENGTH);
			checkMemoryStateAddresses(memoryEntries);
			traceFile.getEntryMemory().updateAll(memoryEntries);
		}
	}

	private static void addEntryRegisters(MorionInitTraceFile traceFile, Map<String, Object> traceFileToConvert)
			throws YamlConverterException {
		Map<String, Object> entryStateMap = getEntryStateMap(traceFileToConvert);
		if (entryStateMap.containsKey(STATE_REGISTERS)) {
			Map<String, List<String>> entryMap = (Map<String, List<String>>) entryStateMap.get(STATE_REGISTERS);
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(entryMap, FOUR_BYTE_LENGTH);
			traceFile.getEntryRegisters().updateAll(memoryEntries);
		}
	}

	private static void addLeaveAddress(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert,
			AddressFactory addressFactory) {
		Map<String, Object> leaveStateMap = getLeaveStateMap(traceFileToConvert);
		if (leaveStateMap.containsKey(STATE_ADDRESS)) {
			String address = (String) leaveStateMap.get(STATE_ADDRESS);
			if (address != null) {
				traceFile.setLeaveAddress(addressFactory.getAddress(address));
			}
		}
	}

	private static void addLeaveMemory(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert)
			throws YamlConverterException {
		Map<String, Object> leaveStateMap = getLeaveStateMap(traceFileToConvert);
		if (leaveStateMap.containsKey(STATE_MEMORY)) {
			Map<String, List<String>> entryMap = (Map<String, List<String>>) leaveStateMap.get(STATE_MEMORY);
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(entryMap, ONE_BYTE_LENGTH);
			checkMemoryStateAddresses(memoryEntries);
			traceFile.getLeaveMemory().updateAll(memoryEntries);
		}
	}

	private static void addLeaveRegisters(MorionTraceFile traceFile, Map<String, Object> traceFileToConvert)
			throws YamlConverterException {
		Map<String, Object> leaveStateMap = getLeaveStateMap(traceFileToConvert);
		if (leaveStateMap.containsKey(STATE_REGISTERS)) {
			Map<String, List<String>> entryMap = (Map<String, List<String>>) leaveStateMap.get(STATE_REGISTERS);
			List<MemoryEntry> memoryEntries = mapToMemoryEntries(entryMap, FOUR_BYTE_LENGTH);
			traceFile.getLeaveRegisters().updateAll(memoryEntries);
		}
	}

	private static void checkMemoryStateAddresses(List<MemoryEntry> memoryEntries) throws YamlConverterException {
		for (MemoryEntry entry : memoryEntries) {
			if (!isValidHex(entry.getName(), FOUR_BYTE_LENGTH)) {
				String message = "Memory state address '" + entry.getName()
						+ "' has to be a hexadecimal no longer than 4 byte";
				throw new YamlConverterException("Illegal memory state address", message);
			}
		}
	}

	private static List<MemoryEntry> mapToMemoryEntries(Map<String, List<String>> entryMap, int maxValueLength)
			throws YamlConverterException {
		if (entryMap == null)
			return new ArrayList<>(); // Ignore, if the mems/regs section is empty

		List<MemoryEntry> entries = new ArrayList<>();
		for (String name : entryMap.keySet()) {
			List<String> details = entryMap.get(name);
			if (details == null || details.size() <= 0) {
				String message = "State " + name + " has no value";
				throw new YamlConverterException("Missing state value", message);
			}
			String value = details.get(0);
			if (!isValidHex(value, maxValueLength)) {
				String message = "State " + name + "'s value has to be a hexadecimal no longer than "
						+ (maxValueLength - 2) / 2 + " byte";
				throw new YamlConverterException("Illegal state value", message);
			}
			boolean symbolic = details.size() > 1
					&& SYMBOLIC.equals(details.get(1));
			entries.add(new MemoryEntry(name, value, symbolic));
		}
		return entries;
	}

	private static Map<String, Object> getEntryStateMap(Map<String, Object> traceFileToConvert) {
		Map<String, Object> entryStateMap = new HashMap<>();
		Map<String, Map<String, Object>> statesMap = getStatesMap(traceFileToConvert);
		if (statesMap.containsKey(ENTRY_STATE)) {
			entryStateMap = statesMap.get(ENTRY_STATE);
		}
		return entryStateMap;
	}

	private static Map<String, Object> getLeaveStateMap(Map<String, Object> traceFileToConvert) {
		Map<String, Object> leaveStateMap = new HashMap<>();
		Map<String, Map<String, Object>> statesMap = getStatesMap(traceFileToConvert);
		if (statesMap.containsKey(LEAVE_STATE)) {
			leaveStateMap = statesMap.get(LEAVE_STATE);
		}
		return leaveStateMap;
	}

	private static Map<String, Map<String, Object>> getStatesMap(Map<String, Object> traceFileToConvert) {
		Map<String, Map<String, Object>> statesMap = new HashMap<>();
		if (traceFileToConvert.containsKey(STATES)) {
			statesMap = (Map<String, Map<String, Object>>) traceFileToConvert.get(STATES);
		}
		return statesMap;
	}

	private static boolean isValidHex(String text, int maxLength) {
		return text.startsWith("0x") && text.substring(2).matches(HEX_REGEX) && text.length() <= maxLength;
	}

}
