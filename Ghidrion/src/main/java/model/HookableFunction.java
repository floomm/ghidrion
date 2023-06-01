package model;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

/**
 * Used when filtering hooks to add to the init trace file.
 */
public class HookableFunction implements Comparable<HookableFunction> {
	private final String name;
	private final String blockName;
	private final Address entryAddress;
	private final Address leaveAddress;

	/**
	 * @param name         of the function
	 * @param entryAddress of the function
	 * @param leaveAddress of the function
	 * @param m            to use for ELF block detection
	 */
	public HookableFunction(String name, Address entryAddress, Address leaveAddress, Memory m) {
		this.name = Objects.requireNonNull(name);
		this.entryAddress = Objects.requireNonNull(entryAddress);
		this.leaveAddress = Objects.requireNonNull(leaveAddress);
		this.blockName = m.getBlock(this.entryAddress) == null ? "undefined" : m.getBlock(this.entryAddress).getName();
	}

	public String getName() {
		return name;
	}

	public String getBlockName() {
		return blockName;
	}

	public Address getEntryAddress() {
		return entryAddress;
	}

	public Address getLeaveAddress() {
		return leaveAddress;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (obj == null || !obj.getClass().equals(this.getClass()))
			return false;
		HookableFunction o = (HookableFunction) obj;
		return o.getEntryAddress().equals(getEntryAddress()) &&
				o.getBlockName().equals(getBlockName()) &&
				o.getName().equals(getName());
	}

	@Override
	public int hashCode() {
		return 3 * name.hashCode() + 5 * blockName.hashCode() + 7 * entryAddress.hashCode();
	}

	@Override
	public int compareTo(HookableFunction o) {
		if (!name.equals(o.getName()))
			return name.compareTo(o.getName());
		if (!blockName.equals(o.getBlockName()))
			return blockName.compareTo(o.getBlockName());
		return entryAddress.compareTo(o.getEntryAddress());
	}

	/**
	 * @param p program to consider
	 * @return all hookable functions in the provided program that are linked to an
	 *         external function.
	 */
	public static Set<HookableFunction> getFunctions(Program p) {
		FunctionManager fm = p.getFunctionManager();
		ReferenceManager rm = p.getReferenceManager();
		Memory m = p.getMemory();
		Set<HookableFunction> res = new HashSet<>();

		for (Function f : fm.getExternalFunctions())
			for (Address a : f.getFunctionThunkAddresses(true))
				for (Reference r : rm.getReferencesTo(a))
					if (!r.isEntryPointReference()) {
						Address entryAddress = r.getFromAddress();
						ghidra.program.model.listing.Instruction i = p.getListing().getInstructionAfter(entryAddress);
						if (i == null) // this happens in .got, where there is no next instruction
							continue;

						Address leaveAddress = i.getAddress();
						res.add(new HookableFunction(f.getName(), entryAddress, leaveAddress, m));
					}

		return res;
	}
}
