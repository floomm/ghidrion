package ctrl;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.LongStream;

import java.util.Set;
import javax.swing.JOptionPane;
import javax.swing.JTable;

import ghidra.util.Msg;
import ghidrion.GhidrionPlugin;
import model.Hook;
import model.HookableFunction;
import model.MemoryEntry;
import model.MorionInitTraceFile;
import model.Hook.Mode;
import util.FileHelper;
import util.MemoryEntryTableModel;
import util.ObservableSet;
import util.TraceFileToYamlConverter;
import util.YamlConverterException;
import util.YamlToTraceFileConverter;

public class InitTraceFileController {
	private final GhidrionPlugin plugin;
	private final MorionInitTraceFile traceFile;

	private final Set<HookableFunction> allHookableFunctions = new HashSet<>();
	private final ObservableSet<HookableFunction> currentlyHookableFunctions = new ObservableSet<>();

	public InitTraceFileController(GhidrionPlugin plugin, MorionInitTraceFile traceFile) {
		this.plugin = Objects.requireNonNull(plugin);
		this.traceFile = Objects.requireNonNull(traceFile);

		plugin.addProgramOpenendListener(p -> {
			allHookableFunctions.clear();
			allHookableFunctions.addAll(HookableFunction.getFunctions(p));
			traceFile.getHooks().clear(); // trigger update of lists
		});
		traceFile.getHooks().addObserver(alreadyHooked -> {
			currentlyHookableFunctions.replaceContent(allHookableFunctions
					.stream()
					.filter(e -> !alreadyHooked
							.stream()
							.map(nH -> nH.getEntryAddress())
							.anyMatch(nH -> nH.equals(e.getAddress())))
					.toList());
		});
	}

	public GhidrionPlugin getPlugin() {
		return plugin;
	}

	public MorionInitTraceFile getTraceFile() {
		return traceFile;
	}

	public void loadTraceFile(Component parent) {
		// Warn user that current init trace file gets cleared
		String warning = "Are you sure you want to proceed? The current editor entries are cleared.";
		int warningResult = JOptionPane.showConfirmDialog(parent, warning, "Confirmation",
				JOptionPane.OK_CANCEL_OPTION);
		if (warningResult != JOptionPane.OK_OPTION) {
			return;
		}

		try {
			YamlToTraceFileConverter.toInitTraceFile(traceFile, FileHelper.getFileStreamToLoad(parent),
					plugin.getCurrentProgram().getAddressFactory());
		} catch (YamlConverterException e) {
			if (e.getCause() != null) {
				Msg.showError(this, parent, e.getTitle(), e.getMessage(), e.getCause());
			} else {
				Msg.showError(this, parent, e.getTitle(), e.getMessage());
			}
		} catch (TraceFileNotFoundException e) {
			Msg.showError(this, parent, "No yaml file", "Select a yaml file to load");
		}
	}

	/**
	 * Write the information in the @param tracefile to a `.yaml` file on disk.
	 * 
	 * @param parent to show the Save As dialog from
	 */
	public void writeTraceFile(Component parent) {
		String content = TraceFileToYamlConverter.toYaml(traceFile);

		File file;
		try {
			file = FileHelper.chooseFile(parent);
		} catch (TraceFileNotFoundException e) {
			Msg.showError(this, parent, "No yaml file", "Select a yaml file to write to", e);
			return;
		}

		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(content.getBytes());
			fos.close();
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}

	public void clearTraceFileListener(ActionEvent e) {
		traceFile.clear();
	}

	private String padHexTo4Bytes(long i) {
		return String.format("0x%8s", Long.toString(i, 16)).replace(' ', '0');
	}

	/**
	 * Adds entries to the init trace file.
	 * 
	 * If no is provided, the {@param value} is split into 1
	 * byte chunks and spread over incrementing addresses starting with
	 * {@param startAddress}.
	 * 
	 * If an {@param endAddress} is provided the {@param value} is repeated for each
	 * byte between the {param startAddress} (inclusive) and {@param endAddress}
	 * (inclusive).
	 * 
	 * Throws up an error message if the value is longer than 1 byte (2 hex chars)
	 * and a non-empty (except for the `0x`) end address is provided.
	 * 
	 * @param startAddress of the new entry
	 * @param endAddress   of the new entry
	 * @param value        of the new entry
	 * @param isSymbolic   true if the new entry is symbolic
	 * @param component    to use to show error messages
	 */
	public void addEntryMemory(
			String startAddress,
			String endAddress,
			String value,
			boolean isSymbolic,
			Component component) {

		if (startAddress.length() <= 2) {
			Msg.showError(this, component, "Empty start address", "Start address can not be empty.");
			return;
		}
		if (value.length() <= 2) {
			Msg.showError(this, component, "Empty value", "Value cannot be empty.");
			return;
		}
		if (endAddress.length() > 2 && value.length() > 4) {
			Msg.showWarn(this, component, "Value does not fit",
					"Please only provide up to one byte (two chars) to add a value to multiple addresses or leave the end address blank to spread the value over an incrementing range of addresses.");
			return;
		}

		if (endAddress.length() > 2)
			repeatMemoryEntry(startAddress, endAddress, component, value, isSymbolic);
		else
			spreadMemoryValue(startAddress, value, isSymbolic, component);
	}

	private void repeatMemoryEntry(String startAddress, String endAddress, Component component, String value,
			boolean isSymbolic) {
		try {
			long startAddressLong = Long.parseLong(startAddress.substring(2), 16);
			long endAddressLong = Long.parseLong(endAddress.substring(2), 16);
			if (startAddressLong > endAddressLong) {
				Msg.showError(this, component, "Illegal end address",
						"End address has to be bigger or equal to start address.");
				return;
			} else
				traceFile.getEntryMemory().replaceAll(LongStream
						.rangeClosed(startAddressLong, endAddressLong)
						.mapToObj(i -> new MemoryEntry(padHexTo4Bytes(i), value,
								isSymbolic))
						.toList());
		} catch (NumberFormatException e) {
			Msg.showError(this, component, "Illegal address value", "Addresses are not a hex value.");
		}
	}

	private void spreadMemoryValue(String startAddress, String value, boolean isSymbolic, Component component) {
		try {
			long startAddressLong = Long.parseLong(startAddress.substring(2), 16);
			Set<MemoryEntry> entriesToAdd = new HashSet<>();
			String e = value.substring(2);
			while (!e.isEmpty()) {
				String startAddressToAdd = padHexTo4Bytes(startAddressLong);
				int charsToAdd = e.length() >= 2 ? 2 : 1;
				String valueToAdd = "0x" + e.substring(0, charsToAdd);
				entriesToAdd.add(new MemoryEntry(startAddressToAdd, valueToAdd, isSymbolic));
				startAddressLong++;
				e = e.substring(charsToAdd);
			}
			traceFile.getEntryMemory().replaceAll(entriesToAdd);
		} catch (NumberFormatException e) {
			Msg.showError(this, component, "Illegal address value", "Addresses are not a hex value.");
		}

	}

	public void removeAllEntryMemory(JTable tableMemory) {
		MemoryEntryTableModel model = (MemoryEntryTableModel) tableMemory.getModel();
		List<MemoryEntry> toDelete = model.getElementsAtRowIndices(tableMemory.getSelectedRows());
		traceFile.getEntryMemory().removeAll(toDelete);
	}

	public void addEntryRegister(String name, String value, boolean isSymbolic, Component component) {
		if (name.isEmpty()) {
			Msg.showError(this, component, "Empty Name", "Name can not be empty.");
			return;
		}
		if (value.length() <= 2) {
			Msg.showError(this, component, "Empty Value", "Value can not be empty.");
			return;
		}
		traceFile.getEntryRegisters().replace(new MemoryEntry(name, value, isSymbolic));
	}

	public void removeAllEntryRegisters(JTable tableRegister) {
		MemoryEntryTableModel model = (MemoryEntryTableModel) tableRegister.getModel();
		List<MemoryEntry> toDelete = model.getElementsAtRowIndices(tableRegister.getSelectedRows());
		traceFile.getEntryRegisters().removeAll(toDelete);
	}

	public ObservableSet<HookableFunction> getCurrentlyHookableFunctions() {
		return currentlyHookableFunctions;
	}

	public void addHooks(List<HookableFunction> hooksToAdd, Mode mode) {
		traceFile.getHooks().replaceAll(hooksToAdd
				.stream()
				.map(e -> new Hook(e.getName(), e.getAddress(), mode))
				.toList());
	}
}
