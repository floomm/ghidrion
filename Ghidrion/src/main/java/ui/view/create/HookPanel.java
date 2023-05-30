package ui.view.create;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;

import model.Hook;
import model.HookableFunction;
import model.Hook.Mode;
import ui.ctrl.CreateController;
import ui.model.HookTableModel;
import ui.view.FilterPanel;

/**
 * Panel where a user can add hooks to their trace file based on external
 * functions in the program as detected by Ghidra. Provides filters based on
 * function name, block name, and address.
 */
public class HookPanel extends JPanel {
    private final CreateController controller;

    private final JLabel labelLibraryName = new JLabel("Library");
    private final JTextField textFieldLibraryName = new JTextField("libc");
    private final FilterPanel<HookableFunction> filterFunctionNames = new FilterPanel<>(HookableFunction::getName,
            "Function Name");
    private final FilterPanel<HookableFunction> filterBlockNames = new FilterPanel<>(HookableFunction::getBlockName,
            "Block Name");;
    private final FilterPanel<HookableFunction> filterAddresses = new FilterPanel<>(f -> f.getAddress().toString(),
            "Address");;
    private final JComboBox<Mode> comboBoxHookMode = new JComboBox<>(new DefaultComboBoxModel<>(Mode.values()));
    private final JButton btnAddHook = new JButton("Add");
    private final HookTableModel tableAddedHooksModel;
    private final JTable tableAddedHooks = new JTable();
    private final JScrollPane scrollPaneAddedHooks = new JScrollPane(tableAddedHooks);
    private final JButton btnDeleteHook = new JButton("Delete");

    public HookPanel(CreateController controller) {
        this.controller = controller;
        this.tableAddedHooksModel = new HookTableModel(controller.getTraceFile().getHooks());
        init();
        setupComponents();
    }

    /**
     * This constructor is solely for debugging the UI.
     * Do NOT use for the plugin.
     */
    public HookPanel() {
        this.controller = null;
        this.tableAddedHooksModel = null;
        init();
    }

    private void init() {
        GridBagLayout gbl_panelHooks = new GridBagLayout();
        gbl_panelHooks.columnWidths = new int[] { 80, 0, 0, 0, 0, 0 };
        gbl_panelHooks.rowHeights = new int[] { 0, 0, 1 };
        gbl_panelHooks.columnWeights = new double[] { 0.3, 1.0, 1.0, 1.0, Double.MIN_VALUE, Double.MIN_VALUE };
        gbl_panelHooks.rowWeights = new double[] { Double.MIN_VALUE, 1.0, 1.0 };
        setLayout(gbl_panelHooks);

        GridBagConstraints gbc_labelLibraryName = new GridBagConstraints();
        gbc_labelLibraryName.gridx = 0;
        gbc_labelLibraryName.gridy = 0;
        add(labelLibraryName, gbc_labelLibraryName);

        GridBagConstraints gbc_textFieldLibraryName = new GridBagConstraints();
        gbc_textFieldLibraryName.gridx = 0;
        gbc_textFieldLibraryName.gridy = 1;
        gbc_textFieldLibraryName.fill = GridBagConstraints.HORIZONTAL;
        add(textFieldLibraryName, gbc_textFieldLibraryName);

        GridBagConstraints gbc_filterFunctionName = new GridBagConstraints();
        gbc_filterFunctionName.gridx = 1;
        gbc_filterFunctionName.gridy = 0;
        gbc_filterFunctionName.gridheight = 2;
        add(filterFunctionNames, gbc_filterFunctionName);

        GridBagConstraints gbc_filterBlockName = new GridBagConstraints();
        gbc_filterBlockName.gridx = 2;
        gbc_filterBlockName.gridy = 0;
        gbc_filterBlockName.gridheight = 2;
        add(filterBlockNames, gbc_filterBlockName);

        GridBagConstraints gbc_filterAddresses = new GridBagConstraints();
        gbc_filterAddresses.gridx = 3;
        gbc_filterAddresses.gridy = 0;
        gbc_filterAddresses.gridheight = 2;
        add(filterAddresses, gbc_filterAddresses);

        GridBagConstraints gbc_comboBoxHookMode = new GridBagConstraints();
        gbc_comboBoxHookMode.gridx = 4;
        gbc_comboBoxHookMode.gridy = 0;
        gbc_comboBoxHookMode.gridheight = 2;
        add(comboBoxHookMode, gbc_comboBoxHookMode);

        GridBagConstraints gbc_btnAddHook = new GridBagConstraints();
        gbc_btnAddHook.gridx = 5;
        gbc_btnAddHook.gridy = 0;
        gbc_btnAddHook.gridheight = 2;
        add(btnAddHook, gbc_btnAddHook);

        GridBagConstraints gbc_tableAddedHooks = new GridBagConstraints();
        gbc_tableAddedHooks.fill = GridBagConstraints.BOTH;
        gbc_tableAddedHooks.gridx = 0;
        gbc_tableAddedHooks.gridy = 2;
        gbc_tableAddedHooks.gridwidth = 5;
        add(scrollPaneAddedHooks, gbc_tableAddedHooks);

        GridBagConstraints gbc_btnDeleteHook = new GridBagConstraints();
        gbc_btnDeleteHook.gridx = 5;
        gbc_btnDeleteHook.gridy = 2;
        add(btnDeleteHook, gbc_btnDeleteHook);
    }

    private void setupComponents() {
        controller.getCurrentlyHookableFunctions().addObserver(filterFunctionNames::updateElements);
        filterFunctionNames.addFilteredElementsObserver(filterBlockNames::updateElements);
        filterBlockNames.addFilteredElementsObserver(filterAddresses::updateElements);
        btnAddHook.addActionListener(event -> controller.addHooks(
                textFieldLibraryName.getText(),
                filterAddresses.getFilteredElements(),
                (Mode) comboBoxHookMode.getSelectedItem()));

        tableAddedHooks.setModel(tableAddedHooksModel);
        tableAddedHooksModel.setColumnHeaders(tableAddedHooks.getColumnModel());

        btnDeleteHook.addActionListener(event -> {
            List<Hook> toDelete = tableAddedHooksModel.getElementsAtRowIndices(tableAddedHooks.getSelectedRows());
            controller.getTraceFile().getHooks().removeAll(toDelete);
            if (tableAddedHooks.getRowCount() > 0)
                tableAddedHooks.getSelectionModel().setSelectionInterval(0, 0);
        });

    }
}
