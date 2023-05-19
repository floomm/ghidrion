package model;

import java.util.Objects;
import java.util.Optional;

/**
 * Entry in the diff tables in the display trace part of the plugin.
 */
public class DiffEntry implements Comparable<DiffEntry> {
    public final String name;
    public final boolean isEntrySymbolic;
    public final boolean isLeaveSymbolic;
    public final String entryValue;
    public final String leaveValue;
    public final boolean isError;
    public final boolean isDiff;

    /**
     * @param name  key
     * @param entry entry on entry
     * @param leave entry on leave
     */
    public DiffEntry(String name, Optional<MemoryEntry> entry, Optional<MemoryEntry> leave) {
        this.name = Objects.requireNonNull(name);
        this.isEntrySymbolic = entry.isPresent() && entry.get().isSymbolic();
        this.isLeaveSymbolic = leave.isPresent() && leave.get().isSymbolic();
        this.isError = entry.isEmpty() || leave.isEmpty();
        this.entryValue = entry.isPresent() ? entry.get().getValue() : "";
        this.leaveValue = leave.isPresent() ? leave.get().getValue() : "";
        this.isDiff = this.entryValue.equals(this.leaveValue);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this)
            return true;
        if (obj == null || !obj.getClass().equals(getClass()))
            return false;
        return name.equals(((DiffEntry) obj).name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

    @Override
    public int compareTo(DiffEntry o) {
        return name.compareTo(o.name);
    }
}
