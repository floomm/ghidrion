package model;

public class MemoryEntry implements Comparable<MemoryEntry> {
    private final String name;
    private final String value;
    private final boolean symbolic;

    public MemoryEntry(String name, String value, boolean symbolic) {
        this.name = name;
        this.value = value;
        this.symbolic = symbolic;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public boolean isSymbolic() {
        return symbolic;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this)
            return true;
        if (obj == null || !this.getClass().equals(obj.getClass()))
            return false;

        MemoryEntry other = (MemoryEntry) obj;
        return this.name.equals(other.name);
    }

    @Override
    public int hashCode() {
        return this.name.hashCode();
    }

    @Override
    public String toString() {
        return (this.symbolic ? "✅\t" : "❎\t") + this.name + "\t" + this.value;
    }

    @Override
    public int compareTo(MemoryEntry o) {
        return this.name.compareTo(o.name);
    }
}