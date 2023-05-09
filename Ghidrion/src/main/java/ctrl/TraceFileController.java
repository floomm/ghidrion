package ctrl;

import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JFileChooser;

import org.yaml.snakeyaml.Yaml;

import model.Hook;
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
		traceFileDump.put(HOOKS, buildHooksDump(traceFile));
		traceFileDump.put(INFO, traceFile.getInfo());
		traceFileDump.put(INSTRUCTIONS, traceFile.getInstructions());
		traceFileDump.put(STATES, traceFile.getStates());
		return traceFileDump;
	}

	private static synchronized String generateTargetAddress() {
		long newTargetAddress = ++targetAddressCounter * TARGET_ADDRESS_STEP;
		return "0x" + Long.toHexString(newTargetAddress);
	}

	private static Map<String, Map<String, List<Map<String, String>>>> buildHooksDump(MorionTraceFile traceFile) {
		Map<String, Map<String, List<Map<String, String>>>> hooksDump = new HashMap<>();

		for (Hook hook : traceFile.getHooks()) {
			Map<String, String> hookDetails = new HashMap<>();
			hookDetails.put(HOOK_ENTRY, "0x" + hook.getEntryAddress().toString());
			hookDetails.put(HOOK_LEAVE, "0x" + hook.getLeaveAddress().toString());
			hookDetails.put(HOOK_TARGET, generateTargetAddress());
			hookDetails.put(HOOK_MODE, hook.getMode().getValue());

			hooksDump.computeIfAbsent(hook.getLibraryName(), k -> new HashMap<>())
					.computeIfAbsent(hook.getFunctionName(), k -> new ArrayList<>())
					.add(hookDetails);
		}

		return hooksDump;
	}
}
