package ghidrion;

import java.awt.Color;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.yaml.snakeyaml.Yaml;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.util.Msg;

public class MorionTraceColorizer {

	private static final String INSTRUCTIONS_KEY = "instructions";
	
	private GhidrionPlugin plugin;
	private ColorizingService colorizingService;
	
	private JComponent parent;

	private Map<String, AddressSet> traces = new HashMap<>();
	
	public MorionTraceColorizer(GhidrionPlugin plugin, JComponent parent) {
		this.plugin = plugin;
		this.parent = parent;
		this.colorizingService = ServiceHelper.getService(plugin.getTool(), ColorizingService.class, this, parent);
	}
	
	/**
	 * Asks for a Morion trace file (.yaml) and sets the background color of the traced instructions to the given color.
	 * 
	 * @param color - the background color
	 * @return the name of the Morion trace file
	 */
	public String colorize(Color color) {
		File traceFile = getTraceFile();
		AddressSet addresses = extractTracedAddresses(traceFile);
		
		String traceName = traceFile.getName();
		traces.put(traceName, addresses);
		String comment = "Trace: " + traceName;

		// Colorize addresses
		if (colorizingService == null) {
			return null;
		}
		int colorizeId = plugin.getCurrentProgram().startTransaction("Colorize " + traceName);
        colorizingService.setBackgroundColor(addresses, color);
        plugin.getCurrentProgram().endTransaction(colorizeId, true);
        
        // Comment addresses
        InstructionIterator iter = plugin.getCurrentProgram().getListing().getInstructions(addresses, true);
		int commentId = plugin.getCurrentProgram().startTransaction("Comment traced addresses");
        while (iter.hasNext()) {
        	Instruction instruction = iter.next();
        	instruction.setComment(CodeUnit.PRE_COMMENT, comment);
        }
        plugin.getCurrentProgram().endTransaction(commentId, true);
        
        // TODO: Jump to start of trace in the Listing window
        
        return traceName;
	}
	
	/**
	 * Clears background color of all instructions of each Morion trace file.  
	 * 
	 * @param traceNames - the names of the Morion trace files
	 */
	public void decolorize(List<String> traceNames) {
		for (String traceName : traceNames) {
			AddressSet addresses = traces.get(traceName);
			
			// Decolorize
			int decolorizeId = plugin.getCurrentProgram().startTransaction("Decolorize " + traceName);
			colorizingService.clearBackgroundColor(addresses);
			plugin.getCurrentProgram().endTransaction(decolorizeId, true);
		}
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

}
