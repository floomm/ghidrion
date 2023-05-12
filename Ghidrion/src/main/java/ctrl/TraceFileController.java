package ctrl;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

import javax.swing.JFileChooser;
import javax.swing.JTable;

import ghidrion.GhidrionPlugin;
import model.MemoryEntry;
import model.MorionTraceFile;
import util.MemoryEntryTableModel;
import util.TraceFileToYamlConverter;

public class TraceFileController {
	private final GhidrionPlugin plugin;
	private final MorionTraceFile traceFile = new MorionTraceFile();
	
	public TraceFileController(GhidrionPlugin plugin) {
		this.plugin = plugin;
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
	 * @param parent    to show the Save As dialog from
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

	public void addEntryMemoryObserver(JTable tableMemory) {
		traceFile.getEntryMemory().addObserver(newList -> {
			List<MemoryEntry> entries = newList.stream().sorted().collect(Collectors.toList());
			MemoryEntryTableModel model = new MemoryEntryTableModel(entries);
			tableMemory.setModel(model);
			model.setColumnHeaders(tableMemory.getColumnModel());
		});
	}

	public void addEntryMemory(String address, String value, boolean isSymbolic) {
		traceFile.getEntryMemory().add(new MemoryEntry(address, value, isSymbolic));
	}

	public void removeAllEntryMemory(JTable tableMemory) {
		MemoryEntryTableModel model = (MemoryEntryTableModel) tableMemory.getModel();
		List<MemoryEntry> toDelete = model.getElementsAtRowIndices(tableMemory.getSelectedRows());
		traceFile.getEntryMemory().removeAll(toDelete);
	}

	public void addEntryRegistersObserver(JTable tableRegister) {
		traceFile.getEntryRegisters().addObserver(newList -> {
			List<MemoryEntry> entries = newList.stream().sorted().collect(Collectors.toList());
			MemoryEntryTableModel model = new MemoryEntryTableModel(entries);
			tableRegister.setModel(model);
			model.setColumnHeaders(tableRegister.getColumnModel());
		});
	}

	public void addEntryRegister(String name, String value, boolean isSymbolic) {
		traceFile.getEntryRegisters().add(new MemoryEntry(name, value, isSymbolic));
	}

	public void removeAllEntryRegisters(JTable tableRegister) {
		MemoryEntryTableModel model = (MemoryEntryTableModel) tableRegister.getModel();
		List<MemoryEntry> toDelete = model.getElementsAtRowIndices(tableRegister.getSelectedRows());
		traceFile.getEntryRegisters().removeAll(toDelete);
	}

}
