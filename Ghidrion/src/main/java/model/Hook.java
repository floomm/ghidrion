package model;

import java.util.Objects;

public class Hook {
	private static final long TARGET_ADDRESS_STEP = 0x100;

	private static long targetAddressCounter = 0;

	private String libraryName;
	private String functionName;
	private String entryAddress;
	private String leaveAddress;
	private String targetAddress;
	private Mode mode;
	
	public Hook(String libraryName, String functionName, String entryAddress, String leaveAddress, Mode mode) {
		this.libraryName = libraryName;
		this.functionName = functionName;
		this.entryAddress = entryAddress;
		this.leaveAddress = leaveAddress;
		this.targetAddress = generateTargetAddress();
		this.mode = mode;
	}
	
	public String getLibraryName() {
		return libraryName;
	}
	
	public String getFunctionName() {
		return functionName;
	}
	
	public String getEntryAddress() {
		return entryAddress;
	}
	
	public String getLeaveAddress() {
		return leaveAddress;
	}
	
	public String getTargetAddress() {
		return targetAddress;
	}
	
	public Mode getMode() {
		return mode;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		Hook other = (Hook) obj;
		return Objects.equals(libraryName, other.libraryName)
				&& Objects.equals(functionName, other.functionName)
				&& Objects.equals(entryAddress, other.entryAddress);
	}

	private static synchronized String generateTargetAddress() {
		long newTargetAddress = ++targetAddressCounter * TARGET_ADDRESS_STEP;
		return "0x" + Long.toHexString(newTargetAddress);
	}
	
	public enum Mode {
		MODEL("model"),
		SKIP("skip"),
		TAINT("taint");

		private final String value;

		Mode(String value) {
			this.value = value;
		}

		public String getValue() {
			return value;
		}
		
		public static Mode fromValue(String value) {
	        for (Mode mode : values()) {
	            if (mode.value.equalsIgnoreCase(value)) {
	                return mode;
	            }
	        }
	        throw new IllegalArgumentException("Invalid Mode value: " + value);
	    }
	}
}
