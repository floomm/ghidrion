package ctrl;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.LongStream;

import java.util.Set;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.filechooser.FileNameExtensionFilter;

import ghidra.util.Msg;
import ghidrion.GhidrionPlugin;
import model.Hook;
import model.HookableFunction;
import model.MemoryEntry;
import model.MorionInitTraceFile;
import model.Hook.Mode;
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
		int warningResult = JOptionPane.showConfirmDialog(null, warning, "Confirmation",
				JOptionPane.OK_CANCEL_OPTION);
		if (warningResult != JOptionPane.OK_OPTION) {
			return;
		}
		traceFile.clear();

		try {
			YamlToTraceFileConverter.toInitTraceFile(traceFile, getFileStreamToLoad(parent), plugin.getCurrentProgram().getAddressFactory());
		} catch (YamlConverterException e) {
			if (e.getCause() != null) {
				Msg.showError(this, parent, e.getTitle(), e.getMessage(), e.getCause());
			} else {
				Msg.showError(this, parent, e.getTitle(), e.getMessage());
			}
		}
	}

	/**
	 * Write the information in the @param tracefile to a `.yaml` file on disk.
	 * 
	 * @param parent to show the Save As dialog from
	 */
	public void writeTraceFile(Component parent) {
		String content = TraceFileToYamlConverter.toYaml(traceFile);

		File file = chooseFile(parent);
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

	public void clearTraceFileListener(ActionEvent e) {
		traceFile.clear();
	}

	public void addEntryMemory(
			String startAddress,
			String endAddress,
			String value,
			boolean isSymbolic,
			Component component) {

		if (startAddress.length() <= 2) {
			Msg.showError(this, component, "Empty Start Address", "Start Address can not be empty.");
			return;
		}
		if (endAddress.length() <= 2) {
			endAddress = startAddress;
		}
		try {
			long startAddressLong = Long.parseLong(startAddress.substring(2), 16);
			long endAddressLong = Long.parseLong(endAddress.substring(2), 16);
			if (startAddressLong > endAddressLong)
				Msg.showError(this, component, "Illegal End Address",
						"End Address has to be bigger or equal to Start Address.");
			else if (value.length() <= 2)
				Msg.showError(this, component, "Empty Value", "Value can not be empty.");
			else
				traceFile.getEntryMemory().replaceAll(LongStream
						.rangeClosed(startAddressLong, endAddressLong)
						.mapToObj(i -> new MemoryEntry("0x" + Long.toString(i, 16), value, isSymbolic))
						.toList());
		} catch (NumberFormatException e) {
			Msg.showError(this, component, "Illegal Address Value", "Addresses are not a hex value.");
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
	
	private File chooseFile(Component parent) {
		JFileChooser fileChooser = new JFileChooser();
		FileNameExtensionFilter filter = new FileNameExtensionFilter("YAML files", "yaml");
		fileChooser.setFileFilter(filter);
		int result = fileChooser.showSaveDialog(parent);
		File file = null;
		if (result == JFileChooser.APPROVE_OPTION) {
			file = fileChooser.getSelectedFile();
		}
		return file;
	}
	
	private FileInputStream getFileStreamToLoad(Component parent) {
		File file = chooseFile(parent);
		FileInputStream input;
		try {
			input = new FileInputStream(file);
		} catch (FileNotFoundException ex) {
			Msg.showError(YamlToTraceFileConverter.class, null, "No trace file", "Couldn't find trace file");
			ex.printStackTrace();
			return null;
		}
		
		return input;
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
