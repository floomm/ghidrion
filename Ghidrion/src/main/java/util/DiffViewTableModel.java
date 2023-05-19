package util;

import java.awt.Color;
import java.awt.Component;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;

import model.DiffEntry;
import model.MemoryEntry;

public class DiffViewTableModel extends CustomTableModel<DiffEntry> {
    private final ObservableSet<MemoryEntry> entry;
    private final ObservableSet<MemoryEntry> leave;
    private final ObservableSet<DiffEntry> diff;

    /**
     * @param diff  for internal use only, is cleared in constructor.
     * @param entry values before trace from loaded YAML
     * @param leave values after trace from loaded YAML
     */
    public DiffViewTableModel(
            ObservableSet<DiffEntry> diff,
            ObservableSet<MemoryEntry> entry,
            ObservableSet<MemoryEntry> leave) {
        super(diff);
        diff.clear();
        this.entry = Objects.requireNonNull(entry);
        this.leave = Objects.requireNonNull(leave);
        this.diff = Objects.requireNonNull(diff);
        entry.addObserver(e -> update());
        leave.addObserver(e -> update());
    }

    private void update() {
        Set<String> keys = new HashSet<>();
        keys.addAll(entry.stream().map(MemoryEntry::getName).toList());
        keys.addAll(leave.stream().map(MemoryEntry::getName).toList());
        diff.replaceContent(keys.stream().map(key -> new DiffEntry(key,
                entry.stream().filter(e -> e.getName().equals(key)).findAny(),
                leave.stream().filter(e -> e.getName().equals(key)).findAny())).toList());
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= getRowCount())
            throw new IllegalArgumentException("Illegal rowIndex");
        switch (columnIndex) {
            case 0:
                return getElements().get(rowIndex).name;
            case 1:
                return getElements().get(rowIndex).entryValue;
            case 2:
                return getElements().get(rowIndex).leaveValue;
            default:
                throw new IllegalArgumentException("Illegal columnIndex");
        }
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public void setColumnHeaders(TableColumnModel columnModel) {
        super.setColumnHeaders(columnModel);
        TableCellRenderer tcr = new TableCellRenderer(this);
        columnModel.getColumns().asIterator().forEachRemaining(column -> column.setCellRenderer(tcr));
    }

    @Override
    protected String getColumnHeader(int i) {
        if (i >= getColumnCount())
            throw new IllegalArgumentException("Column not present");
        return List.of("Name", "Entry Value", "Leave Value").get(i);
    }

    public boolean isRowDiff(int rowIndex) {
        return getElements().get(rowIndex).isDiff;
    }

    public boolean isRowEntrySymbolic(int rowIndex) {
        return getElements().get(rowIndex).isEntrySymbolic;
    }

    public boolean isRowLeaveSymbolic(int rowIndex) {
        return getElements().get(rowIndex).isLeaveSymbolic;
    }

    public boolean isRowError(int rowIndex) {
        return getElements().get(rowIndex).isError;
    }

    private class TableCellRenderer extends DefaultTableCellRenderer {
        private final DiffViewTableModel model;

        public TableCellRenderer(DiffViewTableModel model) {
            this.model = Objects.requireNonNull(model);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
                int row, int column) {

            Color c = Color.BLACK;
            if (model.isRowError(row))
                c = new Color(0xa0, 0, 0);
            else {
                if (column == 0 && model.isRowDiff(row))
                    c = new Color(0, 0xa0, 0);
                else if (column == 1 && model.isRowEntrySymbolic(row))
                    c = new Color(0, 0, 0xa0);
                else if (column == 2 && model.isRowLeaveSymbolic(row))
                    c = new Color(0, 0, 0xa0);
            }

            JLabel label = new JLabel(value.toString());
            label.setForeground(c);
            return label;
        }
    }
}
