package view;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JColorChooser;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import ghidrion.GhidrionPlugin;
import ghidrion.MorionTraceColorizer;

public class DisplayTracePanel extends JPanel {

	private JPanel panel = this;
	private DefaultListModel<String> traceListModel = new DefaultListModel<>();
	private JList<String> traceList = new JList<>(traceListModel);
	
	private MorionTraceColorizer colorizer;
	private Color traceColor = Color.CYAN;

	public DisplayTracePanel() {
		setLayout(new GridLayout(3, 1));
		
		JPanel colorizeTracePanel = new JPanel(new FlowLayout());
		colorizeTracePanel.add(buildDisplayTraceButton());
		colorizeTracePanel.add(buildChooseColorButton());

		add(colorizeTracePanel);
		add(buildRemoveTracesButton());
		add(buildTracesScrollPane());
	}
	
	public void init(GhidrionPlugin plugin) {
		this.colorizer = new MorionTraceColorizer(plugin, this);
	}
	
	/**
	 * @return Button that displays a Morion trace according to {@code MorionTraceColorizer}
	 */
	private JButton buildDisplayTraceButton() {
		JButton importButton = new JButton("Display trace");
		
		importButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String traceName = colorizer.colorize(traceColor);
				traceListModel.addElement(traceName);
			}
		});
		
		return importButton;
	}
	
	/**
	 * @return Button that allows to choose a trace color
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
	
	/**
	 * @return Button that removes the traces selected in the ScrollPane
	 */
	private JButton buildRemoveTracesButton() {
		JButton removeButton = new JButton("Remove selected traces");
		
		removeButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				List<String> selectedItems = traceList.getSelectedValuesList();
				colorizer.decolorize(selectedItems);

				int[] selectedIndices = traceList.getSelectedIndices();
				for (int i : selectedIndices) {
					traceListModel.remove(i);
				}
			}
		});
		
		return removeButton;
	}
	
	private JScrollPane buildTracesScrollPane() {
		JScrollPane tracesScrollPane = new JScrollPane(traceList);
		
		return tracesScrollPane;
	}
}
