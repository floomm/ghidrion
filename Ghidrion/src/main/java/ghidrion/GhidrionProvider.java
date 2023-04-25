package ghidrion;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JColorChooser;
import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ComponentProvider;

public class GhidrionProvider extends ComponentProvider {
	
	public static Color traceColor = Color.BLUE;

	private GhidrionPlugin plugin;
	
	private JPanel panel;

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner) {
		super(plugin.getTool(), pluginName, owner);
		this.plugin = plugin;

		buildPanel();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new GridBagLayout());
		
		panel.add(buildTracePanel());
		
		setVisible(true);
	}
	
	private JPanel buildTracePanel() {
		JPanel tracePanel = new JPanel(new FlowLayout());
		
		// Choose a color for tracing
		JButton colorBtn = new JButton();
		colorBtn.setBackground(traceColor);
		colorBtn.setPreferredSize(new Dimension(25, 25));
		colorBtn.setMinimumSize(new Dimension(20, 20));
		colorBtn.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
                Color newColor = JColorChooser.showDialog(panel, "Choose a color", traceColor);
                if (newColor != null) {
                    traceColor = newColor;
                    colorBtn.setOpaque(true);
                    colorBtn.setBackground(traceColor);
                }
			}
		});
		
		// Import a yaml trace file 
		JButton importTraceBtn = new JButton("Import trace");
		importTraceBtn.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				MorionTraceColorizer colorizer = new MorionTraceColorizer(plugin, tracePanel);
				colorizer.run();
			}
		});
		
		// Clear (decolorize) all Morion traces
		JButton clearTraceBtn = new JButton("Clear trace");
		clearTraceBtn.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO
			}
		});

		// Add all components to panel
		tracePanel.add(importTraceBtn);
		tracePanel.add(colorBtn);
		tracePanel.add(clearTraceBtn);
		
		return tracePanel;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
