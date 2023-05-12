package ghidrion;

import java.util.Objects;
import java.util.Optional;

import docking.Tool;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import model.Hook;
import model.MorionTraceFile;
import model.Hook.Mode;

public class GhidrionHookAddingListingContextAction extends ListingContextAction {
    private static final String LISTENING_CONTEXT_ACTION_NAME = "Ghidrion";
    private static final String MENU_GROUP = "Ghidrion";
    private static final String MENU_PATH_ADD_HOOK = "Ghidrion: Add Hook";
    private static final String MENU_PATH_CHANGE_HOOK = "Ghidrion: Change Hook";
    private static final String DELETE_ENTRY = "delete";
    private final GhidrionPlugin plugin;
    private final MorionTraceFile traceFile;

    public GhidrionHookAddingListingContextAction(GhidrionPlugin plugin, MorionTraceFile traceFile) {
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
                Address a = context.getLocation().getAddress();
                Optional<Function> f = getFunction(context, program);
                traceFile.getHooks().add(new Hook(f.get().getName(), a, mode));
            }

            @Override
            protected boolean isValidContext(ListingActionContext context) {
                Address a = context.getLocation().getAddress();
                Optional<Function> f = getFunction(context, plugin.getCurrentProgram());
                return f.isPresent()
                        && f.get().isExternal()
                        && traceFile
                                .getHooks()
                                .stream()
                                .filter(hook -> hook.getEntryAddress().equals(a))
                                .count() == 0;
            }
        };
    }

    private ListingContextAction getChangeHookAction(Mode mode, Program program) {
        return new ListingContextAction(LISTENING_CONTEXT_ACTION_NAME, getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address a = context.getLocation().getAddress();
                Optional<Function> f = getFunction(context, program);
                traceFile.getHooks().replace(new Hook(f.get().getName(), a, mode));
            }

            @Override
            protected boolean isValidContext(ListingActionContext context) {
                Address a = context.getLocation().getAddress();
                Optional<Function> f = getFunction(context, plugin.getCurrentProgram());
                return f.isPresent()
                        && f.get().isExternal()
                        && traceFile
                                .getHooks()
                                .stream()
                                .filter(hook -> hook.getEntryAddress().equals(a))
                                .filter(hook -> !hook.getMode().equals(mode))
                                .count() > 0;
            }
        };
    }

    private ListingContextAction getDeleteHookAction(Program program) {
        return new ListingContextAction(LISTENING_CONTEXT_ACTION_NAME, getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                Address a = context.getLocation().getAddress();
                Optional<Hook> toDelete = traceFile
                        .getHooks()
                        .stream()
                        .filter(hook -> hook.getEntryAddress().equals(a))
                        .findFirst();
                if (toDelete.isPresent())
                    traceFile.getHooks().remove(toDelete.get());
            }

            @Override
            protected boolean isValidContext(ListingActionContext context) {
                Address a = context.getLocation().getAddress();
                Optional<Function> f = getFunction(context, plugin.getCurrentProgram());
                return f.isPresent()
                        && f.get().isExternal()
                        && traceFile
                                .getHooks()
                                .stream()
                                .filter(hook -> hook.getEntryAddress().equals(a))
                                .count() > 0;
            }
        };
    }

    private static Optional<Function> getFunction(ListingActionContext context, Program p) {
        Reference[] references = p.getReferenceManager()
                .getReferencesFrom(context.getLocation().getAddress());
        if (references.length != 1)
            return Optional.empty();
        Function f = p.getFunctionManager().getFunctionAt(references[0].getToAddress());
        if (f == null)
            return Optional.empty();
        f = f.isThunk() ? f.getThunkedFunction(true) : f;
        return Optional.of(f);

    }
}
