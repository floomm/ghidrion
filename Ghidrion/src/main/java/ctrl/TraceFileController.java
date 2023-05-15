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
import java.util.Set;
import javax.swing.JFileChooser;
import javax.swing.JTable;

import ghidrion.GhidrionPlugin;
import model.Hook;
import model.HookableFunction;
import model.MemoryEntry;
import model.MorionTraceFile;
import model.Hook.Mode;
import util.MemoryEntryTableModel;
import util.ObservableSet;
import util.TraceFileToYamlConverter;

public class TraceFileController {
	private final GhidrionPlugin plugin;
	private final MorionTraceFile traceFile;

	private final Set<HookableFunction> allHookableFunctions = new HashSet<>();
	private final ObservableSet<HookableFunction> currentlyHookableFunctions = new ObservableSet<>();

	public TraceFileController(GhidrionPlugin plugin, MorionTraceFile traceFile) {
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

	public MorionTraceFile getTraceFile() {
		return traceFile;
	}

	/**
	 * Write the information in the @param tracefile to a `.yaml` file on disk.
	 * 
	 * @param parent to show the Save As dialog from
	 */
	public void writeTraceFile(Component parent) {
		String content = TraceFileToYamlConverter.toYaml(traceFile);

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

	public void clearTraceFileListener(ActionEvent e) {
		traceFile.clear();
	}

	public void addEntryMemory(String address, String value, boolean isSymbolic) {
		traceFile.getEntryMemory().replace(new MemoryEntry(address, value, isSymbolic));
	}

	public void removeAllEntryMemory(JTable tableMemory) {
		MemoryEntryTableModel model = (MemoryEntryTableModel) tableMemory.getModel();
		List<MemoryEntry> toDelete = model.getElementsAtRowIndices(tableMemory.getSelectedRows());
		traceFile.getEntryMemory().removeAll(toDelete);
	}

	public void addEntryRegister(String name, String value, boolean isSymbolic) {
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
