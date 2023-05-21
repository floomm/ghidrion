package util;

import java.awt.Color;
import java.util.Objects;

import ghidra.app.decompiler.CTokenHighlightMatcher;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerHighlighter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidrion.GhidrionPlugin;
import model.Instruction;
import model.MorionTraceFile;

/**
 * A {@link GhidraScript} used for (de-)colorizing instructions in the Listing window 
 * and applying highlights in the decompiler based on a given {@link MorionTraceFile} and color.
 */
public class TraceColorizerScript extends GhidraScript {
	
	private final GhidrionPlugin plugin;
	private final AddressSet colorizedAddresses = new AddressSet();

	private DecompilerHighlighter decompilerHighlighter;
	private boolean hasColorizedInstructions = false;
	
	public TraceColorizerScript(GhidrionPlugin plugin) {
		this.plugin = Objects.requireNonNull(plugin);
	}

	/**
	 * Do not use this method, it is an empty implementation.
	 * Instead, use {@link #colorize(MorionTraceFile, Color)} or {@link #decolorize()}.
	 */
	@Override
	protected void run() throws Exception {
	}
	
	/**
     * Colorizes the traced instructions of a given {@link MorionTraceFile} with the specified color.
     *
     * @param traceFile   the MorionTraceFile containing the traced instructions to be colorized
     * @param traceColor  the color to apply to the instructions
     */
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
		if (! goTo(traceFile.getEntryAddress()) && 
				! goTo(traceFile.getLeaveAddress())) {
			// Go to max address if there is no entry or leave address
			// (min address doesn't work because of hook target addresses)
			goTo(addressesToColorize.getMaxAddress()); 
		}
		
		highlightDecompiler(addressesToColorize, traceColor);

		hasColorizedInstructions = true;
	}
	
	/**
     * Decolorizes the previously colorized instructions and clears the decompiler highlights.
     */
	public void decolorize() {
		int decolorizeId = currentProgram.startTransaction("Decolorizing instructions");
		plugin.getColorizingService().clearBackgroundColor(colorizedAddresses);
		currentProgram.endTransaction(decolorizeId, true);
		colorizedAddresses.clear();
		
		if (decompilerHighlighter != null) {
			int clearHighlightsId = currentProgram.startTransaction("Clearing decompiler highlights");
			decompilerHighlighter.clearHighlights();
			decompilerHighlighter.dispose();
			currentProgram.endTransaction(clearHighlightsId, true);
		}

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
