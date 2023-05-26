package ui.ctrl;

import java.awt.Color;
import java.awt.Component;
import java.util.Objects;

import javax.swing.JColorChooser;

import ghidra.util.Msg;
import ghidrion.GhidrionPlugin;
import model.MorionTraceFile;
import util.observable.ObservableColor;
import util.yaml.FileHelper;
import util.yaml.YamlConverterException;
import util.yaml.YamlToTraceFileConverter;

/**
 * Controller for the Trace File Display part of the plugin.
 * See {@link ui.view.display.DisplayPanel} and {@link model.MorionTraceFile}
 */
public class DisplayController {
	private final GhidrionPlugin plugin;
	private final MorionTraceFile traceFile = new MorionTraceFile();
	private final ObservableColor traceColor = new ObservableColor(Color.GREEN);

	public DisplayController(GhidrionPlugin plugin) {
		this.plugin = Objects.requireNonNull(plugin);
		traceFile.getInstructions().addObserver(e -> colorTraceInListing());
		traceColor.addObserver(e -> colorTraceInListing());
	}

	private void colorTraceInListing() {
		plugin.colorizerScript.colorize(traceFile, traceColor.getColor());
	}

	public void clearTrace() {
		traceFile.clear();
		plugin.colorizerScript.decolorize();
	}

	/**
	 * Displays a color picker and changes the background color in the listings view
	 * accordingly.
	 * 
	 * @param component to use for the popup
	 */
	public void updateTraceColor(Component component) {
		Color newColor = JColorChooser.showDialog(component, "Choose a color", traceColor.getColor());
		if (newColor != null)
			traceColor.setColor(newColor);
	}

	/**
	 * Displays a popup for the user to choose a new trace file to load and display.
	 * 
	 * @param component to use for popups
	 */
	public void loadTraceFile(Component component) {
		try {
			YamlToTraceFileConverter.toTraceFile(traceFile, FileHelper.getFileStreamToLoad(component),
					plugin.getCurrentProgram().getAddressFactory());
		} catch (TraceFileNotFoundException ex) {
			return;
		} catch (YamlConverterException ex) {
			Msg.showError(component, component, ex.getTitle(), ex.getMessage(), ex);
			ex.printStackTrace();
		}
	}

	public MorionTraceFile getTraceFile() {
		return traceFile;
	}

	public ObservableColor getTraceColor() {
		return traceColor;
	}
}
