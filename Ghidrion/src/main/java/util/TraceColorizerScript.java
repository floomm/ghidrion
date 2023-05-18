package util;

import java.awt.Color;

import ghidra.app.decompiler.CTokenHighlightMatcher;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerHighlighter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidrion.GhidrionPlugin;
import model.Instruction;
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
		
		AddressSet addressesToColorize = new AddressSet();
		for (Instruction i : traceFile.getInstructions()) {
			addressesToColorize.add(i.getAddress());
		}
		
		int colorizeId = currentProgram.startTransaction("Colorizing instructions");
		plugin.getColorizingService().setBackgroundColor(addressesToColorize, traceColor);
		currentProgram.endTransaction(colorizeId, true);
		colorizedAddresses.add(addressesToColorize);
		goTo(traceFile.getEntryAddress());
		
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

}
