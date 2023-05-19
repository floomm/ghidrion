package model;

import ghidra.program.model.address.Address;

public class Instruction implements Comparable<Instruction> {
	private final Address address;
	private final String machineCode;
	private final String assemblyCode;
	private final String code;
	
	public Instruction(Address address, String machineCode, String assemblyCode, String code) {
		this.address = address;
		this.machineCode = machineCode;
		this.assemblyCode = assemblyCode;
		this.code = code;
	}
	
	public Address getAddress() {
		return address;
	}
	
	public String getMachineCode() {
		return machineCode;
	}
	
	public String getAssemblyCode() {
		return assemblyCode;
	}
	
	public String getCode() {
		return code;
	}

    @Override
    public boolean equals(Object obj) {
        if (obj == this)
            return true;
        if (obj == null || !this.getClass().equals(obj.getClass()))
            return false;

        Instruction other = (Instruction) obj;
        return this.address.toString().equals(other.address.toString());
    }

    @Override
    public int hashCode() {
        return this.address.toString().hashCode();
    }

	@Override
	public int compareTo(Instruction o) {
        return this.address.toString().compareTo(o.address.toString());
	}

}
