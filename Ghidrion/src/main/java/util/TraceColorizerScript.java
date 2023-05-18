package util;

import java.awt.Color;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.yaml.snakeyaml.Yaml;

import ghidra.app.decompiler.CTokenHighlightMatcher;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerHighlighter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidrion.GhidrionPlugin;

public class TraceColorizerScript extends GhidraScript {
	
	private static final String INSTRUCTIONS_KEY = "instructions";

	private final GhidrionPlugin plugin;
	private final AddressSet colorizedAddresses = new AddressSet();

	private DecompilerHighlighter decompilerHighlighter;
	private boolean hasColorizedInstructions = false;
	
	public TraceColorizerScript(GhidrionPlugin plugin) {
		this.plugin = plugin;
	}

	@Override
	protected void run() throws Exception {
	}
	
	public void colorize(Color traceColor) {
		if (hasColorizedInstructions) {
			decolorize();
		}
		
		File traceFile = getTraceFile();
		if (traceFile == null) {
			return;
		}
		
		AddressSet addressesToColorize = getTracedAddresses(traceFile);
		
		int colorizeId = currentProgram.startTransaction("Colorizing instructions");
		plugin.getColorizingService().setBackgroundColor(addressesToColorize, traceColor);
		currentProgram.endTransaction(colorizeId, true);
		colorizedAddresses.add(addressesToColorize);
		// TODO: The address set also contains hooked addresses
		goTo(addressesToColorize.getMaxAddress());
		
		highlightDecompiler(addressesToColorize, traceColor);

		hasColorizedInstructions = true;
	}
	
	public void decolorize() {
		int decolorizeId = currentProgram.startTransaction("Decolorizing instructions");
		plugin.getColorizingService().clearBackgroundColor(colorizedAddresses);
		currentProgram.endTransaction(decolorizeId, true);
		colorizedAddresses.clear();
		
		int clearHighlightsId = currentProgram.startTransaction("Clearing decompiler highlights");
		decompilerHighlighter.clearHighlights();
		decompilerHighlighter.dispose();
		currentProgram.endTransaction(clearHighlightsId, true);

		hasColorizedInstructions = false;
	}
	
	private void highlightDecompiler(AddressSet addresses, Color color) {
		DecompilerHighlighter highlighter = createHighlighter(addresses, color);
		this.decompilerHighlighter = highlighter;
		highlighter.applyHighlights();
	}

	private DecompilerHighlighter createHighlighter(AddressSet addresses, Color color) {
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
		return plugin.getDecompilerHighlightService().createHighlighter(highlightMatcher);
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
