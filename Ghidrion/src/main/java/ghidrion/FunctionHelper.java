package ghidrion;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.Lists;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class FunctionHelper {
	private final Program p;

	public FunctionHelper(Program p) {
		if (p == null) throw new IllegalArgumentException();
		this.p = p;
	}

	public Set<Address> getAddressesForFunction(String functionName) {
		return getFunctions().get(functionName);
	}

	public Set<Address> getAddressesForFunction(String functionName, String blockName) {
		MemoryBlock b = p.getMemory().getBlock(blockName);
		return getAddressesForFunction(functionName).stream().filter(e -> b.contains(e)).collect(Collectors.toSet());
	}

	public Set<String> getAllBlocks() {
		return Arrays.stream(p.getMemory().getBlocks()).map(MemoryBlock::getName).collect(Collectors.toSet());
	}

	public Set<String> getFunctionNames() {
		return getFunctions().keySet();
	}

	public Set<String> getFunctionNames(String blockName) {
		MemoryBlock b = p.getMemory().getBlock(blockName);
		Set<String> res = new HashSet<>();
		for (Entry<String, Set<Address>> entry : getFunctions().entrySet()) {
			if (entry.getValue().stream().filter(e -> b.contains(e)).count() > 0)
				res.add(entry.getKey());
		}
		return res;
	}

	private Map<String, Set<Address>> getFunctions() {
		FunctionManager fm = p.getFunctionManager();
		ReferenceManager rm = p.getReferenceManager();
		Map<String, Set<Address>> res = new HashMap<>();
		for (Function f : fm.getExternalFunctions()) {
			Set<Address> thunkAddresses = new HashSet<>(Lists.newArrayList(f.getFunctionThunkAddresses(true)));
			for (Address a : thunkAddresses) {
				String name = fm.getFunctionAt(a).getName();
				res.putIfAbsent(name, new HashSet<>());
				for (Reference r : rm.getReferencesTo(a)) {
					res.get(name).add(r.getFromAddress());
				}
			}
		}
		return res;
	}

}
