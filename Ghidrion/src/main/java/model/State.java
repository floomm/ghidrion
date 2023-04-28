package model;

import java.util.ArrayList;
import java.util.LinkedHashMap;

public class State {
	
	public static final String SYMBOLIC = "$$";
	
	private StateType stateType;
	private String addr;
    private LinkedHashMap<String, ArrayList<String>> mems = new LinkedHashMap<>();
    private LinkedHashMap<String, ArrayList<String>> regs = new LinkedHashMap<>();
    
    public State(StateType stateType) {
    	this.stateType = stateType;
	}
    
    public void setAddr(String addr) {
		this.addr = addr;
	}
    
    public void addRegister(String registerName, String registerValue, boolean isSymbolic) {
    	ArrayList<String> register = new ArrayList<>();
    	register.add(registerValue);
    	if (isSymbolic) {
    		register.add(SYMBOLIC);
    	}
    	regs.put(registerName, register);
    }
    
    public void addMemory(String memoryAddress, String memoryValue, boolean isSymbolic) {
    	ArrayList<String> memory = new ArrayList<>();
    	memory.add(memoryValue);
    	if (isSymbolic) {
    		memory.add(SYMBOLIC);
    	}
    	mems.put(memoryAddress, memory);
    }
	
	public enum StateType {
		Entry,
		Leave
	}
}
