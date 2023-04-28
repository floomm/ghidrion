package model;

import java.util.ArrayList;
import java.util.LinkedHashMap;

import model.State.StateType;

public class MorionTraceFile {

	private LinkedHashMap<String, LinkedHashMap<String, ArrayList<LinkedHashMap<String, String>>>> hooks = new LinkedHashMap<>();
	private LinkedHashMap<String, String> info = new LinkedHashMap<>();
	private ArrayList<ArrayList<String>> instructions = new ArrayList<>();
	private State entryState = new State(StateType.Entry);
	private State leaveState = new State(StateType.Leave);
	private LinkedHashMap<String, State> states = new LinkedHashMap<>();
	
	public void addHook(String libraryName, String functionName, String entryAddress, String leaveAddress, String targetAddress, String mode) {
		LinkedHashMap<String, ArrayList<LinkedHashMap<String, String>>> hook = new LinkedHashMap<>();
		ArrayList<LinkedHashMap<String, String>> function = new ArrayList<>();
		LinkedHashMap<String, String> functionItem = new LinkedHashMap<>();
		functionItem.put("entry", entryAddress);
		functionItem.put("leave", leaveAddress);
		functionItem.put("target", targetAddress);
		functionItem.put("mode", mode);
		function.add(functionItem);
		hook.put(functionName, function);
		hooks.put(libraryName, hook);
	}
	
	public void addEntryStateRegister(String name, String value, boolean isSymbolic) {
		entryState.addRegister(name, value, isSymbolic);
	}
	
	public void addEntryStateMemory(String address, String value, boolean isSymbolic) {
		entryState.addMemory(address, value, isSymbolic);
	}

}
