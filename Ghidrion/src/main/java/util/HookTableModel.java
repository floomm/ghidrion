package util;

import java.util.List;

import model.Hook;

public class HookTableModel extends CustomTableModel<Hook> {
    public HookTableModel(ObservableSet<Hook> hooks) {
        super(hooks);
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex >= getRowCount() || columnIndex >= getColumnCount())
            throw new IllegalArgumentException("Invalid rowIndex or columnIndex");
        Hook h = getElements().get(rowIndex);
        switch (columnIndex) {
            case 0:
                return h.getLibraryName();
            case 1:
                return h.getFunctionName();
            case 2:
                return h.getEntryAddress().toString();
            case 3:
                return h.getMode();
            default:
                throw new IllegalArgumentException();
        }
    }

    @Override
    protected String getColumnHeader(int i) {
        if (i >= getColumnCount())
            throw new IllegalArgumentException("Column not present");
        return List.of("Library", "Function", "Address", "Mode").get(i);
    }
}
