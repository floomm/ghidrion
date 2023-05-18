package model;

import java.util.Objects;
import java.util.Optional;

import ghidra.program.model.address.Address;

public class Hook implements Comparable<Hook> {
	private final String libraryName = "libc";
	private final String functionName;
	private final Address entryAddress;
	private final Mode mode;

	public Hook(String functionName, Address entryAddress, Mode mode) {
		this.functionName = Objects.requireNonNull(functionName);
		this.entryAddress = Objects.requireNonNull(entryAddress);
		this.mode = Objects.requireNonNull(mode);
	}

	public String getLibraryName() {
		return libraryName;
	}

	public String getFunctionName() {
		return functionName;
	}

	public Address getEntryAddress() {
		return entryAddress;
	}

	public Address getLeaveAddress() {
		return entryAddress.next();
	}

	public Mode getMode() {
		return mode;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null || getClass() != obj.getClass())
			return false;
		Hook other = (Hook) obj;
		return Objects.equals(libraryName, other.libraryName)
				&& Objects.equals(functionName, other.functionName)
				&& Objects.equals(entryAddress, other.entryAddress);
	}

	@Override
	public int hashCode() {
		return libraryName.hashCode() * 3 + functionName.hashCode() * 5 + entryAddress.hashCode() * 7;
	}

	@Override
	public int compareTo(Hook o) {
		if (!this.libraryName.equals(o.libraryName))
			return this.libraryName.compareTo(o.libraryName);
		if (!this.functionName.equals(o.functionName))
			return this.functionName.compareTo(o.functionName);
		return this.entryAddress.compareTo(o.entryAddress);
	}

	public enum Mode {
		MODEL("model"),
		SKIP("skip"),
		TAINT("taint");

		private final String value;

		Mode(String value) {
			this.value = Objects.requireNonNull(value);
		}

		public String getValue() {
			return value;
		}

		public static Optional<Mode> fromValue(String value) {
			for (Mode mode : values()) {
				if (mode.value.equalsIgnoreCase(value)) {
					return Optional.of(mode);
				}
			}
			return Optional.empty();
		}

		@Override
		public String toString() {
			return this.value;
		}
	}

}
