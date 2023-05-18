package util;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.decompiler.CTokenHighlightMatcher;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerHighlighter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidrion.GhidrionPlugin;
import model.MorionTraceFile;

public class TraceColorizerScript extends GhidraScript {
	
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
	
	public void colorize(MorionTraceFile traceFile, Color traceColor) {
		if (hasColorizedInstructions) {
			decolorize();
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
	
	private AddressSet getTracedAddresses(MorionTraceFile traceFile) {
        List<String> addressList = traceFile.getInstructions().stream()
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
