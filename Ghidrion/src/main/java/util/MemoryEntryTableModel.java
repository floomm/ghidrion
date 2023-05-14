package util;

import java.util.List;

import model.MemoryEntry;

public class MemoryEntryTableModel extends CustomTableModel<MemoryEntry> {

    public MemoryEntryTableModel(ObservableSet<MemoryEntry> hooks) {
        super(hooks);
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex >= getRowCount() || columnIndex >= getColumnCount())
            throw new IllegalArgumentException("Invalid rowIndex or columnIndex");

        MemoryEntry m = getElements().get(rowIndex);
        switch (columnIndex) {
            case 0:
                return m.isSymbolic() ? "✅" : "❌";
            case 1:
                return m.getName();
            case 2:
                return m.getValue();
            default:
                throw new IllegalArgumentException();
        }
    }

    @Override
    protected String getColumnHeader(int i) {
        if (i >= getColumnCount())
            throw new IllegalArgumentException("Column not present");

        return List.of("Symbolic", "Name", "Value").get(i);
    }
}
