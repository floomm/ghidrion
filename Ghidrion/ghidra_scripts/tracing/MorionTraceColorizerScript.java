package tracing;


import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.util.Msg;
import ghidrion.GhidrionProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.yaml.snakeyaml.Yaml;

public class MorionTraceColorizerScript extends GhidraScript {
	
	private static final String INSTRUCTIONS_KEY = "instructions";

	@Override
	public void run() throws Exception {
		ColorizingService colorizingService = state.getTool().getService(ColorizingService.class);
		
		if (colorizingService == null) {
			println("Can't find ColorizingService service");
			return;
		}
		
        // Prompt the user to select a trace file
        File traceFile = askFile("Select File", "OK");

        // Check if the user selected a file
        if (traceFile == null) {
            Msg.info(this, "No file selected");
            return;
        }
        
        InputStream input = new FileInputStream(traceFile);
        
        // Load the yaml trace file as a Map
        Yaml yaml = new Yaml();
        Map<String, Collection> trace = (LinkedHashMap<String, Collection>) yaml.load(input);
        
        // Get the traced instructions
        ArrayList<ArrayList<String>> tracedInstructions = (ArrayList<ArrayList<String>>) trace.get(INSTRUCTIONS_KEY);
        
        // Get the memory addresses of the traced instructions
        ArrayList<String> tracedAddresses = tracedInstructions.stream()
        		.filter(instruction -> !instruction.isEmpty())
        		.map(instruction -> instruction.get(0))
        		.map(address -> address.substring(2))
        		.collect(Collectors.toCollection(ArrayList::new));
        
        
        AddressSet addresses = new AddressSet();
        for (String address : tracedAddresses) {
        	addresses.add(parseAddress(address));
        }
        
        colorizingService.setBackgroundColor(addresses, GhidrionProvider.traceColor);
		
	}

}
