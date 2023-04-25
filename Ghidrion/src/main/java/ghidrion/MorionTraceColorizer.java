package ghidrion;

import java.awt.Color;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.yaml.snakeyaml.Yaml;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.program.model.address.AddressSet;
import ghidra.util.Msg;

public class MorionTraceColorizer {

	private static final String INSTRUCTIONS_KEY = "instructions";
	
	private GhidrionPlugin plugin;
	private JComponent parent;
	
	public MorionTraceColorizer(GhidrionPlugin plugin, JComponent parent) {
		this.plugin = plugin;
		this.parent = parent;
	}
	
	public String run(Color color) {
		File traceFile = getTraceFile();
		
		AddressSet addresses = extractTracedAddresses(traceFile);
        
        // TODO: Jump to start of trace in the Listing window
        
		colorize(addresses, color);
        
        return traceFile.getName();
	}
	
	private File getTraceFile() {
		JFileChooser fileChooser = new JFileChooser();

		// Filter for yaml files
		FileNameExtensionFilter filter = new FileNameExtensionFilter("YAML files", "yaml");
		fileChooser.setFileFilter(filter);

		int returnState = fileChooser.showOpenDialog(parent);
		if (returnState == JFileChooser.APPROVE_OPTION) {
			Msg.info(this, "Imported file: " + fileChooser.getSelectedFile().getName());
		}
		
		return fileChooser.getSelectedFile();
	}
	
	private AddressSet extractTracedAddresses(File traceFile) {
        InputStream input;
		try {
			input = new FileInputStream(traceFile);
		} catch (FileNotFoundException e) {
			Msg.showError(this, parent, "No trace file", "Can't find " + traceFile.getName(), e);
			return null;
		}
        
        // Load the yaml trace file as a Map
        Yaml yaml = new Yaml();
        Map<String, Collection> trace = (LinkedHashMap<String, Collection>) yaml.load(input);
        
        // Get the traced instructions
        ArrayList<ArrayList<String>> instructions = (ArrayList<ArrayList<String>>) trace.get(INSTRUCTIONS_KEY);
        
        // Get the memory addresses of the traced instructions as strings
        ArrayList<String> hexAddresses = instructions.stream()
        		.filter(instruction -> !instruction.isEmpty())
        		.map(instruction -> instruction.get(0))
        		.map(address -> address.substring(2)) // remove leading 0x
        		.collect(Collectors.toCollection(ArrayList::new));
        
        // Convert to AddressSet
        AddressSet addresses = new AddressSet();
        for (String address : hexAddresses) {
        	addresses.add(plugin.getFlatAPI().toAddr(address));
        }

        return addresses;
	}
	
	private void colorize(AddressSet addresses, Color color) {
		ColorizingService colorizingService = ServiceHelper.getService(plugin.getTool(), ColorizingService.class, this, parent);
		if (colorizingService == null) {
			return;
		}
		
		int id = plugin.getCurrentProgram().startTransaction("Colorize traced addresses");
        colorizingService.setBackgroundColor(addresses, color);
        plugin.getCurrentProgram().endTransaction(id, true);
	}
}
