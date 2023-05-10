package ctrl;

import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.JFileChooser;

import org.yaml.snakeyaml.Yaml;

import model.Hook;
import model.MemoryEntry;
import model.MorionTraceFile;

public class TraceFileController {

	private static final long TARGET_ADDRESS_STEP = 0x100;
	private static long targetAddressCounter = 0;

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

	public static void writeTraceFile(Component parent, MorionTraceFile traceFile) {
		Yaml yaml = new Yaml();

		String content = yaml.dump(buildTraceFileDump(traceFile));

		JFileChooser fileChooser = new JFileChooser();
		int result = fileChooser.showSaveDialog(parent);
		File file = null;
		if (result == JFileChooser.APPROVE_OPTION) {
			file = fileChooser.getSelectedFile();
		}

		if (file != null) {
			try (FileOutputStream fos = new FileOutputStream(file)) {
				fos.write(content.getBytes());
				fos.close();
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		}
	}

	private static Map<String, Object> buildTraceFileDump(MorionTraceFile traceFile) {
		Map<String, Object> traceFileDump = new HashMap<>();
		traceFileDump.put(HOOKS, getHooksMap(traceFile));
		traceFileDump.put(STATES, getStatesMap(traceFile));
		// traceFileDump.put(INFO, traceFile.getInfo());
		// traceFileDump.put(INSTRUCTIONS, traceFile.getInstructions());
		return traceFileDump;
	}

	private static Map<String, Map<String, Map<String, List<String>>>> getStatesMap(MorionTraceFile traceFile) {
		return Map.of(ENTRY_STATE,
				Map.of(
						STATE_REGISTERS, memoryEntriesToMap(traceFile.getEntryRegisters()),
						STATE_MEMORY, memoryEntriesToMap(traceFile.getEntryMemory())));
	}

	private static Map<String, List<String>> memoryEntriesToMap(Collection<MemoryEntry> ms) {
		return ms
				.stream()
				.map(m -> new Pair<>(m.name, m.symbolic ? List.of(m.value, SYMBOLIC) : List.of(m.value)))
				.collect(Collectors.toMap(Pair::getA, Pair::getB));
	}

	private static synchronized String generateTargetAddress() {
		long newTargetAddress = ++targetAddressCounter * TARGET_ADDRESS_STEP;
		return prependHex(Long.toHexString(newTargetAddress));
	}

	private static String prependHex(Object s) {
		return "0x" + s.toString();
	}

	private static Map<String, Map<String, List<Map<String, String>>>> getHooksMap(MorionTraceFile traceFile) {
		return traceFile.getHooks()
				.stream()
				.collect(Collectors.groupingBy(Hook::getLibraryName, Collectors.toList()))
				.entrySet()
				.stream()
				.map(e -> new Pair<>(e.getKey(), getHooksByFunctionName(e.getValue())))
				.collect(Collectors.toMap(e -> e.getA(), e -> e.getB()));
	}

	private static Map<String, List<Map<String, String>>> getHooksByFunctionName(Collection<Hook> hooks) {
		return hooks.stream()
				.collect(Collectors.groupingBy(e -> e.getFunctionName(),
						Collectors.mapping(TraceFileController::getHookMap, Collectors.toList())));
	}

	private static Map<String, String> getHookMap(Hook hook) {
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
