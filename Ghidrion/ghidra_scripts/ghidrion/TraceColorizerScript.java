package ghidrion;

import java.awt.Color;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.yaml.snakeyaml.Yaml;

import ghidra.app.decompiler.CTokenHighlightMatcher;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerHighlighter;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public class TraceColorizerScript extends GhidraScript {
	
	private static final String INSTRUCTIONS_KEY = "instructions";

	private GhidrionPlugin plugin;
	private ColorizingService colorizingService;
	
	private Map<String, AddressSet> traces = new HashMap<>();
	private Map<String, DecompilerHighlighter> highlighters = new HashMap<>();
	
	public TraceColorizerScript(GhidrionPlugin plugin) {
		this.plugin = plugin;
	}

	@Override
	protected void run() throws Exception {
	}
	
	public String colorize(Color traceColor) {
		colorizingService = plugin.getColorizingService();
		
		File traceFile = getTraceFile();
		if (traceFile == null) {
			return null;
		}
		
		String traceName = traceFile.getName();
		
		if (traces.containsKey(traceName)) {
			Msg.showInfo(this, null, "Trace already exists", "A trace of file " + traceName + " already exists");
			return null;
		}
		
		AddressSet addresses = getTracedAddresses(traceFile);
		
		int colorizeId = currentProgram.startTransaction("Colorize " + traceName);
		colorizingService.setBackgroundColor(addresses, traceColor);
		currentProgram.endTransaction(colorizeId, true);
		
		traces.put(traceName, addresses);
		
		// TODO: The address set also contains hooked addresses
		plugin.jumpToAddressScript.run(addresses.getMaxAddress());
		
		highlightDecompiler(addresses, traceColor, traceName);
		
		return traceName;
	}
	
	public void decolorize(List<String> traceNames) {
		for (String traceName : traceNames) {
			// Clear background colors in Listing window
			AddressSet addresses = traces.get(traceName);
			int decolorizeId = currentProgram.startTransaction("Decolorize" + traceName);
			colorizingService.clearBackgroundColor(addresses);
			currentProgram.endTransaction(decolorizeId, true);
			
			// Clear highlights in Decompiler window
			DecompilerHighlighter decompilerHighlighter = highlighters.get(traceName);
			int clearHighlightsId = currentProgram.startTransaction("Clear highlight" + traceName);
			decompilerHighlighter.clearHighlights();
			decompilerHighlighter.dispose();
			currentProgram.endTransaction(clearHighlightsId, true);
			highlighters.remove(traceName);
		}
	}
	
	private void highlightDecompiler(AddressSet addresses, Color color, String traceName) {
		DecompilerHighlighter decompilerHighlighter = createHighlighter(addresses, color, traceName);
		highlighters.put(traceName, decompilerHighlighter);
		decompilerHighlighter.applyHighlights();
	}

	private DecompilerHighlighter createHighlighter(AddressSet addresses, Color color, String traceName) {
		CTokenHighlightMatcher highlightMatcher = new CTokenHighlightMatcher() {
			@Override
			public Color getTokenHighlight(ClangToken token) {
				if (token.getMinAddress() == null || token.getMaxAddress() == null) {
					return null;
				}
				if (addresses.contains(token.getMinAddress()) && addresses.contains(token.getMaxAddress())) {
					return color;
				}
				return null;
			}
		};
		DecompilerHighlighter decompilerHighlighter = plugin.getDecompilerHighlightService().createHighlighter(traceName, highlightMatcher);
		return decompilerHighlighter;
	}

	private File getTraceFile() {
		File traceFile;
		try {
			traceFile = askFile("Select Trace File", "OK");
		} catch (CancelledException e) {
            Msg.info(this, "No trace file selected");
            return null;
		}
		if (! traceFile.getName().endsWith(".yaml")) {
            Msg.showError(this, null, "No yaml file", "Trace file has to be a .yaml file");
			return null;
		}
		
		return traceFile;
	}
	
	private AddressSet getTracedAddresses(File traceFile) {
		InputStream input;
		try {
			input = new FileInputStream(traceFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			Msg.showError(this, null, "No trace file", "Couldn't find the Morion trace file");
			return null;
		}
		
		Yaml yaml = new Yaml();
        Map<String, Object> trace = (LinkedHashMap<String, Object>) yaml.load(input);
        List<List<String>> instructions = (List<List<String>>) trace.get(INSTRUCTIONS_KEY);
        List<String> addressList = instructions.stream()
        		.filter(instruction -> !instruction.isEmpty())
        		.map(instruction -> instruction.get(0))
        		.map(address -> address.substring(2))
        		.collect(Collectors.toCollection(ArrayList::new));
        AddressSet addressSet = new AddressSet();
        for (String address : addressList) {
        	addressSet.add(parseAddress(address));
        }
		return addressSet;
	}

}
