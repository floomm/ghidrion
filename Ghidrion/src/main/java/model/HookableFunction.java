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
	private final Address address;

	/**
	 * @param name    of the function
	 * @param address of the function
	 * @param m       to use for ELF block detection
	 */
	public HookableFunction(String name, Address address, Memory m) {
		this.name = Objects.requireNonNull(name);
		this.address = Objects.requireNonNull(address);
		this.blockName = m.getBlock(this.address).getName();
	}

	public String getName() {
		return name;
	}

	public String getBlockName() {
		return blockName;
	}

	public Address getAddress() {
		return address;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (obj == null || !obj.getClass().equals(this.getClass()))
			return false;
		HookableFunction o = (HookableFunction) obj;
		return o.getAddress().equals(getAddress()) &&
				o.getBlockName().equals(getBlockName()) &&
				o.getName().equals(getName());
	}

	@Override
	public int hashCode() {
		return 3 * name.hashCode() + 5 * blockName.hashCode() + 7 * address.hashCode();
	}

	@Override
	public int compareTo(HookableFunction o) {
		if (!name.equals(o.getName()))
			return name.compareTo(o.getName());
		if (!blockName.equals(o.getBlockName()))
			return blockName.compareTo(o.getBlockName());
		return address.compareTo(o.getAddress());
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

		Set<Address> thunkAddresses = new HashSet<>();
		for (Function f : fm.getExternalFunctions()) {
			for (Address a : f.getFunctionThunkAddresses(true))
				thunkAddresses.add(a);
		}
		for (Address a : thunkAddresses) {
			String name = fm.getFunctionAt(a).getName();
			for (Reference r : rm.getReferencesTo(a))
				res.add(new HookableFunction(name, r.getFromAddress(), m));
		}
		return res;
	}
}
