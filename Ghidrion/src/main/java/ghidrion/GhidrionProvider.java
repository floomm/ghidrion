package ghidrion;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JColorChooser;
import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ComponentProvider;
import ghidra.app.services.GhidraScriptService;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;

public class GhidrionProvider extends ComponentProvider {
	
	public static Color traceColor = Color.BLUE;

	private Plugin plugin;
	private Program currentProgram;
	private FlatProgramAPI flatAPI;
	private GhidraScriptService scriptService;
	
	private JPanel panel;

	public GhidrionProvider(Plugin plugin, String pluginName, String owner, Program currentProgram) {
		super(plugin.getTool(), pluginName, owner);
		this.plugin = plugin;
		this.currentProgram = currentProgram;
		if (currentProgram != null) {
			this.flatAPI = new FlatProgramAPI(currentProgram);
		}

		buildPanel();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		
		panel.add(buildTracePanel());
		
		setVisible(true);
	}
	
	private JPanel buildTracePanel() {
		JPanel tracePanel = new JPanel(new FlowLayout());
		
		// Choose a color for tracing
		JButton colorBtn = new JButton();
		colorBtn.setBackground(traceColor);
		colorBtn.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
                Color newColor = JColorChooser.showDialog(panel, "Choose Color", traceColor);
                if (newColor != null) {
                    traceColor = newColor;
                    colorBtn.setBackground(traceColor);
                }
			}
		});
		
		// Import a yaml trace file 
		JButton pickTraceFileBtn = new JButton("Import trace");
		pickTraceFileBtn.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				scriptService = ServiceHelper.getService(plugin.getTool(), GhidraScriptService.class);
				scriptService.runScript("/tracing/MorionTraceColorizerScript.java", null);
			}
		});
		
		// Clear (decolorize) all Morion traces
		JButton clearTracesBtn = new JButton("Clear trace");
		// TODO: ClearMorionTracesScript

		// Add all components to panel
		tracePanel.add(pickTraceFileBtn);
		tracePanel.add(colorBtn);
		tracePanel.add(clearTracesBtn);
		
		return tracePanel;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	public void setProgram(Program currentProgram) {
		this.currentProgram = currentProgram;
		this.flatAPI = new FlatProgramAPI(currentProgram);
	}

}
