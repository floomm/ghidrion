package ghidrion;

import java.util.Objects;
import java.util.Optional;

import javax.swing.JOptionPane;

import docking.Tool;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import model.Hook;
import model.MorionInitTraceFile;
import model.Hook.Mode;

/**
 * Adds the following context actions to the Ghidra listing entries that contain
 * a hookable function:
 * 
 * <ul>
 * <li>If a function is not yet hooked an entry that allows you to hook it with
 * each {@link model.Hook.Mode}</li>
 * <li>If a function is already hooked an entry that allows you to hook it with
 * the other {@link model.Hook.Mode}</li>
 * <li>If a function is already hooked an entry that allows you to delete the
 * hook</li>
 * </ul>
 */
public class GhidrionHookListingContextMenu extends ListingContextAction {
    private static final String LISTENING_CONTEXT_ACTION_NAME = "Ghidrion";
    private static final String MENU_GROUP = "Ghidrion";
    private static final String MENU_PATH_ADD_HOOK = "Ghidrion: Add Hook";
    private static final String MENU_PATH_CHANGE_HOOK = "Ghidrion: Change Hook";
    private static final String DELETE_ENTRY = "delete hook";
    private final GhidrionPlugin plugin;
    private final MorionInitTraceFile traceFile;

    public GhidrionHookListingContextMenu(GhidrionPlugin plugin, MorionInitTraceFile traceFile) {
        super("Ghidrion", plugin.getName());
        plugin.addProgramOpenendListener(this::programOpened);
        this.plugin = Objects.requireNonNull(plugin);
        this.traceFile = Objects.requireNonNull(traceFile);
    }

    private void programOpened(Program program) {
        plugin.getTool().setMenuGroup(new String[] { MENU_PATH_ADD_HOOK }, MENU_GROUP);
        for (Mode mode : Mode.values()) {
            addAction(plugin.getTool(), MENU_PATH_ADD_HOOK, mode.getValue(), getAddHookAction(mode, program));
            addAction(plugin.getTool(), MENU_PATH_CHANGE_HOOK, mode.getValue(), getChangeHookAction(mode, program));
        }
        addAction(plugin.getTool(), MENU_PATH_CHANGE_HOOK, DELETE_ENTRY, getDeleteHookAction(program));
    }

    private void addAction(Tool tool, String parent, String child, ListingContextAction action) {
        action.setPopupMenuData(new MenuData(new String[] { parent, child }, null, MENU_GROUP));
        tool.addAction(action);
    }

    private ListingContextAction getAddHookAction(Mode mode, Program program) {
        return new ListingContextAction(LISTENING_CONTEXT_ACTION_NAME, getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address entryAddress = context.getLocation().getAddress();
                Address leaveAddress = program.getListing().getInstructionAfter(entryAddress).getAddress();
                Optional<Function> function = getFunctionAtSelectedLocation(context, program);
                String name = function.get().getName(); // checks are done in isValidContext
                String libraryName = JOptionPane.showInputDialog("Input library name", "libc");
                traceFile.getHooks().add(new Hook(libraryName, name, entryAddress, leaveAddress, mode));
            }

            @Override
            protected boolean isValidContext(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                Optional<Function> function = getFunctionAtSelectedLocation(context, plugin.getCurrentProgram());
                return function.isPresent()
                        && function.get().isExternal()
                        && traceFile
                                .getHooks()
                                .stream()
                                .filter(hook -> hook.getEntryAddress().equals(address))
                                .count() == 0;
            }
        };
    }

    private ListingContextAction getChangeHookAction(Mode mode, Program program) {
        return new ListingContextAction(LISTENING_CONTEXT_ACTION_NAME, getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address entryAddress = context.getLocation().getAddress();
                Address leaveAddress = program.getListing().getInstructionAfter(entryAddress).getAddress();
                Optional<Function> function = getFunctionAtSelectedLocation(context, program);
                String name = function.get().getName(); // checks are done in isValidContext
                String libraryName = traceFile
                        .getHooks()
                        .stream()
                        .filter(hook -> hook.getEntryAddress().equals(entryAddress))
                        .findFirst()
                        .get()
                        .getLibraryName();
                traceFile.getHooks().update(new Hook(libraryName, name, entryAddress, leaveAddress, mode));
            }

            @Override
            protected boolean isValidContext(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                Optional<Function> function = getFunctionAtSelectedLocation(context, plugin.getCurrentProgram());
                return function.isPresent()
                        && function.get().isExternal()
                        && traceFile
                                .getHooks()
                                .stream()
                                .filter(hook -> hook.getEntryAddress().equals(address))
                                .filter(hook -> !hook.getMode().equals(mode))
                                .count() > 0;
            }
        };
    }

    private ListingContextAction getDeleteHookAction(Program program) {
        return new ListingContextAction(LISTENING_CONTEXT_ACTION_NAME, getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                traceFile
                        .getHooks()
                        .stream()
                        .filter(hook -> hook.getEntryAddress().equals(address))
                        .forEach(hook -> traceFile.getHooks().remove(hook));
            }

            @Override
            protected boolean isValidContext(ListingActionContext context) {
                Address address = context.getLocation().getAddress();
                Optional<Function> function = getFunctionAtSelectedLocation(context, plugin.getCurrentProgram());
                return function.isPresent()
                        && function.get().isExternal()
                        && traceFile
                                .getHooks()
                                .stream()
                                .filter(hook -> hook.getEntryAddress().equals(address))
                                .count() > 0;
            }
        };
    }

    private static Optional<Function> getFunctionAtSelectedLocation(ListingActionContext context, Program p) {
        Reference[] references = p.getReferenceManager()
                .getReferencesFrom(context.getLocation().getAddress());
        if (references.length != 1)
            return Optional.empty();
        Function function = p.getFunctionManager().getFunctionAt(references[0].getToAddress());
        if (function == null)
            return Optional.empty();
        function = function.isThunk() ? function.getThunkedFunction(true) : function;
        return Optional.of(function);
    }
}
