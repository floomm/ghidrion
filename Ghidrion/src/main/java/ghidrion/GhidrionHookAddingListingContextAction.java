package ghidrion;

import java.util.Objects;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import model.Hook;
import model.MorionTraceFile;
import model.Hook.Mode;

public class GhidrionHookAddingListingContextAction extends ListingContextAction {
    private static final String MENU_PATH_ADD_HOOK = "Add Ghidrion Hook";
    private static final String MENU_GROUP = "Ghidrion";
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
            ListingContextAction listingContextAction = new ListingContextAction("LCA1", getName()) {
                @Override
                protected void actionPerformed(ListingActionContext context) {
                    Address a = context.getLocation().getAddress();
                    Program p = plugin.getCurrentProgram();
                    Reference[] references = p.getReferenceManager().getReferencesFrom(a);
                    if (references.length != 1)
                        Msg.error(this, "Invalid number of references from this address");
                    String functionName = p.getFunctionManager().getFunctionAt(references[0].getToAddress()).getName();
                    traceFile.getHooks().add(new Hook(functionName, a, mode));
                }

                @Override
                protected boolean isValidContext(ListingActionContext context) {
                    Program p = plugin.getCurrentProgram();
                    Reference[] references = p.getReferenceManager()
                            .getReferencesFrom(context.getLocation().getAddress());
                    if (references.length != 1)
                        return false;
                    Function f = p.getFunctionManager().getFunctionAt(references[0].getToAddress());
                    if (f == null)
                        return false;
                    f = f.isThunk() ? f.getThunkedFunction(true) : f;
                    return f.isExternal();
                }
            };

            listingContextAction.setPopupMenuData(
                    new MenuData(new String[] { MENU_PATH_ADD_HOOK, mode.getValue() }, null, MENU_GROUP));
            plugin.getTool().addAction(listingContextAction);

        }
    }

}
