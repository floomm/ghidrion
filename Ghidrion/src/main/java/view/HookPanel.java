package view;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.List;

import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidrion.GhidrionPlugin;
import model.FunctionHelper;
import model.Hook;
import model.MorionTraceFile;
import model.Hook.Mode;
import util.HookTableModel;

public class HookPanel extends JPanel {
    private final MorionTraceFile traceFile;
    private final GhidrionPlugin plugin;
    private FunctionHelper functionHelper;

    protected final JLabel lblFunctionNamed = new JLabel("Block Name");
    protected final JLabel lblFunctionName = new JLabel("Function Name");
    protected final JLabel lblFunctionAddress = new JLabel("Function Address");
    protected final JList<String> listBlockName = new JList<>();
    protected final JList<Address> listFunctionAddress = new JList<>();
    protected final JLabel lblMode = new JLabel("Mode");
    protected final JComboBox<Mode> comboBoxHookMode = new JComboBox<>();
    protected final JButton btnAddHook = new JButton("Add");
    protected final JList<String> listFunctionName = new JList<String>();
    private final JTable tableAddedHooks = new JTable();
    private final JScrollPane scrollPaneAddedHooks = new JScrollPane(tableAddedHooks);
    protected final JButton btnDeleteHook = new JButton("Delete");

    public HookPanel(GhidrionPlugin plugin, MorionTraceFile traceFile) {
        this.traceFile = traceFile;
        this.plugin = plugin;

        GridBagLayout gbl_panelHooks = new GridBagLayout();
        gbl_panelHooks.columnWidths = new int[] { 100, 100, 100, 0, 0 };
        gbl_panelHooks.rowHeights = new int[] { 0, 100, 100 };
        gbl_panelHooks.columnWeights = new double[] { 1.0, 1.0, 1.0, 0.0, 1.0 };
        gbl_panelHooks.rowWeights = new double[] { 1.0, 1.0, 1.0 };
        setLayout(gbl_panelHooks);

        GridBagConstraints gbc_lblFunctionName = new GridBagConstraints();
        gbc_lblFunctionName.insets = new Insets(0, 0, 5, 5);
        gbc_lblFunctionName.gridx = 0;
        gbc_lblFunctionName.gridy = 0;
        add(lblFunctionName, gbc_lblFunctionName);

        GridBagConstraints gbc_lblFunctionNamed = new GridBagConstraints();
        gbc_lblFunctionNamed.insets = new Insets(0, 0, 5, 5);
        gbc_lblFunctionNamed.gridx = 1;
        gbc_lblFunctionNamed.gridy = 0;
        add(lblFunctionNamed, gbc_lblFunctionNamed);

        GridBagConstraints gbc_lblFunctionAddress = new GridBagConstraints();
        gbc_lblFunctionAddress.insets = new Insets(0, 0, 5, 5);
        gbc_lblFunctionAddress.gridx = 2;
        gbc_lblFunctionAddress.gridy = 0;
        add(lblFunctionAddress, gbc_lblFunctionAddress);

        GridBagConstraints gbc_lblMode = new GridBagConstraints();
        gbc_lblMode.insets = new Insets(0, 0, 5, 5);
        gbc_lblMode.gridx = 3;
        gbc_lblMode.gridy = 0;
        add(lblMode, gbc_lblMode);

        GridBagConstraints gbc_listAddedHooks = new GridBagConstraints();
        gbc_listAddedHooks.gridwidth = 4;
        gbc_listAddedHooks.insets = new Insets(0, 0, 0, 5);
        gbc_listAddedHooks.fill = GridBagConstraints.BOTH;
        gbc_listAddedHooks.gridx = 0;
        gbc_listAddedHooks.gridy = 2;
        add(scrollPaneAddedHooks, gbc_listAddedHooks);

        GridBagConstraints gbc_listFunctionName = new GridBagConstraints();
        gbc_listFunctionName.insets = new Insets(0, 0, 5, 5);
        gbc_listFunctionName.fill = GridBagConstraints.BOTH;
        gbc_listFunctionName.gridx = 0;
        gbc_listFunctionName.gridy = 1;
        listFunctionName.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        add(listFunctionName, gbc_listFunctionName);

        GridBagConstraints gbc_listBlockName = new GridBagConstraints();
        gbc_listBlockName.insets = new Insets(0, 0, 5, 5);
        gbc_listBlockName.fill = GridBagConstraints.BOTH;
        gbc_listBlockName.gridx = 1;
        gbc_listBlockName.gridy = 1;
        add(listBlockName, gbc_listBlockName);

        GridBagConstraints gbc_listFunctionAddress = new GridBagConstraints();
        gbc_listFunctionAddress.insets = new Insets(0, 0, 5, 5);
        gbc_listFunctionAddress.fill = GridBagConstraints.BOTH;
        gbc_listFunctionAddress.gridx = 2;
        gbc_listFunctionAddress.gridy = 1;
        add(listFunctionAddress, gbc_listFunctionAddress);

        GridBagConstraints gbc_comboBoxHookMode = new GridBagConstraints();
        gbc_comboBoxHookMode.insets = new Insets(0, 0, 5, 5);
        gbc_comboBoxHookMode.fill = GridBagConstraints.HORIZONTAL;
        gbc_comboBoxHookMode.gridx = 3;
        gbc_comboBoxHookMode.gridy = 1;
        comboBoxHookMode.setModel(new DefaultComboBoxModel<>(Mode.values()));
        add(comboBoxHookMode, gbc_comboBoxHookMode);

        GridBagConstraints gbc_btnAddHook = new GridBagConstraints();
        gbc_btnAddHook.insets = new Insets(0, 0, 5, 0);
        gbc_btnAddHook.gridx = 4;
        gbc_btnAddHook.gridy = 1;
        add(btnAddHook, gbc_btnAddHook);

        GridBagConstraints gbc_btnDeleteHook = new GridBagConstraints();
        gbc_btnDeleteHook.gridx = 4;
        gbc_btnDeleteHook.gridy = 2;
        add(btnDeleteHook, gbc_btnDeleteHook);

        setupComponents();
    }

    private void setupComponents() {
        plugin.addProgramOpenendListener(this::setupHookLists);
        traceFile.getHooks().addObserver((h) -> setupHookLists(plugin.getCurrentProgram()));
        setupBtnAddHook();
        setupListAddedHooks();
        setupBtnDeleteHook();
    }

    private void setupHookLists(Program p) {
        functionHelper = new FunctionHelper(p);
        DefaultListModel<String> functionNameModel = new DefaultListModel<>();
        List<String> functionNames = functionHelper
                .getFunctionNames(traceFile.getHooks())
                .stream()
                .sorted()
                .collect(Collectors.toList());
        functionNameModel.addAll(functionNames);
        listFunctionName.setModel(functionNameModel);
        listFunctionName.addListSelectionListener((ListSelectionEvent e) -> {
            List<String> blockNames = functionHelper
                    .getBlockNames(traceFile.getHooks(), listFunctionName.getSelectedValuesList())
                    .stream()
                    .sorted()
                    .collect(Collectors.toList());
            DefaultListModel<String> blockNameModel = new DefaultListModel<>();
            blockNameModel.addAll(blockNames);
            listBlockName.setModel(blockNameModel);
            listBlockName.addListSelectionListener((ListSelectionEvent e2) -> {
                List<Address> addresses = functionHelper
                        .getAddresses(traceFile.getHooks(), listFunctionName.getSelectedValuesList(),
                                listBlockName.getSelectedValuesList())
                        .stream()
                        .sorted()
                        .collect(Collectors.toList());
                DefaultListModel<Address> addressesModel = new DefaultListModel<>();
                addressesModel.addAll(addresses);
                listFunctionAddress.setModel(addressesModel);
                listFunctionAddress.setSelectedIndices(IntStream.range(0, addresses.size()).toArray());
            });
            listBlockName.setSelectedIndices(IntStream.range(0, blockNames.size()).toArray());
        });
    }

    private void setupBtnAddHook() {
        btnAddHook.addActionListener(e -> {
            String functionName = listFunctionName.getSelectedValue();
            Mode mode = (Mode) comboBoxHookMode.getSelectedItem();
            List<Hook> toAdd = listFunctionAddress.getSelectedValuesList().stream().map(
                    a -> new Hook(functionName, a, mode)).collect(Collectors.toList());
            traceFile.getHooks().replaceAll(toAdd);
        });
    }

    private void setupListAddedHooks() {
        traceFile.getHooks().addObserver(newSet -> {
            List<Hook> hooks = newSet.stream().sorted().collect(Collectors.toList());
            HookTableModel model = new HookTableModel(hooks);
            tableAddedHooks.setModel(model);
            model.setColumnHeaders(tableAddedHooks.getColumnModel());
        });
    }

    private void setupBtnDeleteHook() {
        btnDeleteHook.addActionListener(e -> {
            HookTableModel model = (HookTableModel) tableAddedHooks.getModel();
            List<Hook> toDelete = model.getElementsAtRowIndices(tableAddedHooks.getSelectedRows());
            traceFile.getHooks().removeAll(toDelete);
            tableAddedHooks.getSelectionModel().setSelectionInterval(0, 0);
        });
    }

}
