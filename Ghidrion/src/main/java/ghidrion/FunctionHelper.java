package ghidrion;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
		if (p == null)
			throw new IllegalArgumentException();
		this.p = p;
	}

	public Set<Address> getAddresses(Collection<String> functionNames, Collection<String> blockNames) {
		return getFunctions()
				.entrySet()
				.stream()
				.filter(e -> functionNames.contains(e.getKey()))
				.flatMap(e -> e.getValue().stream())
				.filter(a -> getBlockStream(blockNames).anyMatch(b -> b.contains(a)))
				.collect(Collectors.toSet());
	}

	public Set<String> getBlockNames(Collection<String> functionNames) {
		return getFunctions()
				.entrySet()
				.stream()
				.filter(f -> functionNames.contains(f.getKey()))
				.flatMap(f -> f.getValue().stream())
				.map(a -> p.getMemory().getBlock(a))
				.map(b -> b.getName())
				.collect(Collectors.toSet());
	}

	private Stream<MemoryBlock> getBlockStream(Collection<String> blockNames) {
		return blockNames
				.stream()
				.map(e -> p.getMemory().getBlock(e));
	}

	public Set<String> getFunctionNames() {
		return getFunctions().keySet();
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
