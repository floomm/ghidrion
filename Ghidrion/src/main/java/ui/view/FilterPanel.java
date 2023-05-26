package ui.view;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

import javax.swing.DefaultListModel;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.text.PlainDocument;

import ui.ctrl.FilterPanelController;

/**
 * Contains a list that can be filtered using a regular expression in a text
 * field above. All selected elements (or all elements if none are selected) are
 * passed to the output.
 */
public class FilterPanel<E extends Comparable<E>> extends JPanel {
    private final JTextField filter = new JTextField();
    private final JList<String> list = new JList<>();
    private final JScrollPane listScrollPane = new JScrollPane(list);
    private final JLabel title;

    private final FilterPanelController<E> controller;

    /**
     * @param displayMapper used to transform the elements to their display
     *                      representation.
     * @param title         to display above the text field
     */
    public FilterPanel(Function<E, String> displayMapper, String title) {
        DefaultListModel<String> listModel = new DefaultListModel<>();
        PlainDocument filterDocument = new PlainDocument();
        this.list.setModel(listModel);
        this.filter.setDocument(filterDocument);
        this.title = new JLabel(title);
        this.controller = new FilterPanelController<>(displayMapper, listModel, filterDocument,
                filter.getHighlighter());
        this.list.addListSelectionListener(
                event -> controller.updateSelectedElements(list.getSelectedValuesList()));

        GridBagLayout gbl = new GridBagLayout();
        gbl.rowHeights = new int[] { 0, 0, 100 };
        gbl.rowWeights = new double[] { Double.MIN_VALUE, Double.MIN_VALUE, 1.0 };
        gbl.columnWidths = new int[] { 100 };
        gbl.columnWeights = new double[] { 1.0 };
        setLayout(gbl);
        GridBagConstraints titleGBC = new GridBagConstraints();
        titleGBC.gridx = 0;
        titleGBC.gridy = 0;
        titleGBC.fill = GridBagConstraints.HORIZONTAL;
        add(this.title, titleGBC);
        GridBagConstraints filterGBC = new GridBagConstraints();
        filterGBC.gridx = 0;
        filterGBC.gridy = 1;
        filterGBC.fill = GridBagConstraints.HORIZONTAL;
        add(this.filter, filterGBC);
        GridBagConstraints listGBC = new GridBagConstraints();
        listGBC.gridx = 0;
        listGBC.gridy = 2;
        listGBC.fill = GridBagConstraints.BOTH;
        add(this.listScrollPane, listGBC);
    }

    /**
     * @param newElements that should be filtered by this component.
     */
    public void updateElements(Collection<E> newElements) {
        controller.updateElements(newElements);
    }

    /**
     * @param observer triggered whenever the filter or selection changes with all
     *                 passing elements.
     */
    public void addFilteredElementsObserver(Consumer<List<E>> observer) {
        controller.getOutputList().addObserver(observer);
    }

    /**
     * @return all elements currently passing the filter.
     */
    public List<E> getFilteredElements() {
        return new ArrayList<>(controller.getOutputList());
    }
}
