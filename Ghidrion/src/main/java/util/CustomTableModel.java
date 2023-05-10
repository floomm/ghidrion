package util;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;

/**
 * This TableModel implementation can be used if a certain class of objects
 * should be displayed in a table. It provides the mapping between table entries
 * and objects.
 */
public abstract class CustomTableModel<E> extends AbstractTableModel {
    private final List<E> elements;

    public CustomTableModel(List<E> elements) {
        this.elements = Objects.requireNonNull(elements);
    }

    @Override
    public int getRowCount() {
        return elements.size();
    }

    protected List<E> getElements() {
        return elements;
    }

    public List<E> getElementsAtRowIndices(int[] is) {
        return Arrays.stream(is).mapToObj(i -> elements.get(i)).collect(Collectors.toList());
    }

    /**
     * Called in {@link CustomTableModel#setColumnHeaders(TableColumnModel)} for
     * {@param i}s between 0 and {@link CustomTableModel#getColumnCount()}.
     * 
     * @param i the ith column
     * @return the title of the column
     */
    protected abstract String getColumnHeader(int i);

    public void setColumnHeaders(TableColumnModel columnModel) {
        for (int i = 0; i < getColumnCount(); i++) {
            columnModel.getColumn(i).setHeaderValue(getColumnHeader(i));
        }
    }
}
