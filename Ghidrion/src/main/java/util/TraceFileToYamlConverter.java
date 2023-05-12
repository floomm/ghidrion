package util;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.yaml.snakeyaml.Yaml;

import model.Hook;
import model.MemoryEntry;
import model.MorionTraceFile;

public class TraceFileToYamlConverter {

	public static final String HOOKS = "hooks";
	public static final String HOOK_ENTRY = "entry";
	public static final String HOOK_LEAVE = "leave";
	public static final String HOOK_TARGET = "target";
	public static final String HOOK_MODE = "mode";
	public static final String INFO = "info";
	public static final String INSTRUCTIONS = "instructions";
	public static final String STATES = "states";
	public static final String ENTRY_STATE = "entry";
	public static final String LEAVE_STATE = "leave";
	public static final String STATE_ADDRESS = "addr";
	public static final String STATE_MEMORY = "mems";
	public static final String STATE_REGISTERS = "regs";
	public static final String SYMBOLIC = "$$";

	private static final long TARGET_ADDRESS_STEP = 0x100;
	private static long targetAddressCounter = 0;

	/**
	 * Convert the information in the @param traceFile to yaml code.
	 * 
	 * @param 	traceFile to write to disk
	 * @return 	traceFile as yaml code
	 */
	public static String toYaml(MorionTraceFile traceFile) {
		Map<String, Object> traceFileDump = new HashMap<>();
		traceFileDump.put(HOOKS, getHooksMap(traceFile));
		traceFileDump.put(STATES, getStatesMap(traceFile));
		// traceFileDump.put(INFO, traceFile.getInfo());
		// traceFileDump.put(INSTRUCTIONS, traceFile.getInstructions());
		return new Yaml().dump(traceFileDump);
	}

	private static Map<String, Map<String, Map<String, List<String>>>> getStatesMap(MorionTraceFile traceFile) {
		return Map.of(ENTRY_STATE,
				Map.of(
						STATE_REGISTERS, memoryEntriesToMap(traceFile.getEntryRegisters()),
						STATE_MEMORY, memoryEntriesToMap(traceFile.getEntryMemory())));
	}
	

	private static Map<String, List<String>> memoryEntriesToMap(Collection<MemoryEntry> ms) {
		return new TreeMap<>(ms
				.stream()
				.map(m -> new Pair<>(m.getName(),
						m.isSymbolic() ? List.of(m.getValue(), SYMBOLIC) : List.of(m.getValue())))
				.collect(Collectors.toMap(Pair::getA, Pair::getB)));
	}

	private synchronized static String generateTargetAddress() {
		long newTargetAddress = ++targetAddressCounter * TARGET_ADDRESS_STEP;
		return prependHex(Long.toHexString(newTargetAddress));
	}

	private static String prependHex(Object s) {
		return "0x" + s.toString();
	}

	private static Map<String, Map<String, List<Map<String, String>>>> getHooksMap(MorionTraceFile traceFile) {
		return new TreeSet<>(traceFile.getHooks()) // convert to TreeSet to sort hooks
				.stream()
				.collect(
						Collectors.groupingBy(
								Hook::getLibraryName,
								TreeMap::new, // sort library names
								Collectors.groupingBy(
										Hook::getFunctionName,
										TreeMap::new, // sort function names
										Collectors.mapping(TraceFileToYamlConverter::hookToMap, Collectors.toList()))));
	}

	private static Map<String, String> hookToMap(Hook hook) {
		Map<String, String> hookMap = new HashMap<>();
		hookMap.put(HOOK_ENTRY, prependHex(hook.getEntryAddress()));
		hookMap.put(HOOK_LEAVE, prependHex(hook.getLeaveAddress()));
		hookMap.put(HOOK_TARGET, generateTargetAddress());
		hookMap.put(HOOK_MODE, hook.getMode().getValue());
		return hookMap;
	}

	public static class Pair<A, B> {
		private final A a;
		private final B b;

		public Pair(A a, B b) {
			this.a = a;
			this.b = b;
		}

		public A getA() {
			return a;
		}

		public B getB() {
			return b;
		}
	}
}
