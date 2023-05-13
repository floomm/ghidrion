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

public class HookableFunction implements Comparable<HookableFunction> {
	private final String name;
	private final String blockName;
	private final Address address;

	public HookableFunction(String name, Address a, Memory m) {
		this.name = Objects.requireNonNull(name);
		this.address = Objects.requireNonNull(a);
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

	// public static Set<HookableFunction> getFunctions(Program p) {
	// FunctionManager fm = p.getFunctionManager();
	// ReferenceManager rm = p.getReferenceManager();
	// Memory m = p.getMemory();
	// Set<HookableFunction> res = new HashSet<>();

	// Set<Address> addressesOfExternalFunctions = new HashSet<>();
	// for (Function externalFunction : fm.getExternalFunctions())
	// for (Address a : externalFunction.getFunctionThunkAddresses(true))
	// addressesOfExternalFunctions.add(a);

	// for (Address a : addressesOfExternalFunctions) {
	// System.out.println(a);
	// Function f = fm.getFunctionAt(a);
	// if (f != null)
	// res.add(new HookableFunction(f.getName(), a, m));
	// for (Reference r : rm.getReferencesTo(a)) {
	// Address a2 = r.getFromAddress();
	// Function f2 = fm.getFunctionAt(a2);
	// if (f2 != null)
	// res.add(new HookableFunction(f2.getName(), a2, m));
	// }
	// }
	// return res;
	// }

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
