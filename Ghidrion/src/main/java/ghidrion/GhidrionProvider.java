package ghidrion;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JColorChooser;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.ComponentProvider;

public class GhidrionProvider extends ComponentProvider {
	
	private Color traceColor = Color.CYAN;

	private GhidrionPlugin plugin;
	
	private JPanel panel;
	
	private DefaultListModel<String> traceListModel = new DefaultListModel<>();
	private JList<String> traceList = new JList<>(traceListModel);

	public GhidrionProvider(GhidrionPlugin plugin, String pluginName, String owner) {
		super(plugin.getTool(), pluginName, owner);
		this.plugin = plugin;

		buildPanel();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new GridLayout(6, 1));
		panel.add(new JLabel("Create a Morion trace file"));
		panel.add(new JPanel());
		panel.add(new JLabel("Trace an execution"));
		panel.add(new JPanel());
		panel.add(new JLabel("Display Morion trace file"));
		panel.add(buildDisplayTracePanel());
		
		setVisible(true);
	}
	
	private JPanel buildDisplayTracePanel() {
		JPanel displayTracePanel = new JPanel(new GridLayout(2, 1));
		
		JPanel panel1 = new JPanel(new FlowLayout());
		panel1.add(buildDisplayTraceButton());
		panel1.add(buildChooseColorButton());
		panel1.add(buildRemoveTracesButton());
		
		displayTracePanel.add(panel1);
		displayTracePanel.add(buildTracesScrollPane());
		
		return displayTracePanel;
	}
	
	/**
	 * @return Button which allows to choose a trace color
	 */
	private JButton buildChooseColorButton() {
		JButton colorButton = new JButton();

		colorButton.setBackground(traceColor);
		colorButton.setPreferredSize(new Dimension(25, 25));
		colorButton.setMinimumSize(new Dimension(20, 20));

		colorButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
                Color newColor = JColorChooser.showDialog(panel, "Choose a color", traceColor);
                if (newColor != null) {
                    traceColor = newColor;
                    colorButton.setBackground(traceColor);
                    colorButton.setOpaque(true);
                }
			}
		});
		
		return colorButton;
	}
	
	private JButton buildDisplayTraceButton() {
		JButton importButton = new JButton("Display trace");
		
		importButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				MorionTraceColorizer colorizer = new MorionTraceColorizer(plugin, panel);
				String traceName = colorizer.run(traceColor);
				if (traceName != null) {
					traceListModel.addElement(traceName);
				}
			}
		});
		
		return importButton;
	}
	
	private JButton buildRemoveTracesButton() {
		JButton removeButton = new JButton("Remove selected traces");
		
		removeButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				int selectedIndex = traceList.getSelectedIndex();
				if (selectedIndex != -1) {
					traceListModel.remove(selectedIndex);
				}
			}
		});
		
		return removeButton;
	}
	
	private JScrollPane buildTracesScrollPane() {
		JScrollPane tracesScrollPane = new JScrollPane(traceList);
		
		return tracesScrollPane;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
