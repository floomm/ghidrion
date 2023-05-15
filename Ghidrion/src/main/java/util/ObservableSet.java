package util;

import java.util.HashSet;
import java.util.Set;

public class ObservableSet<E extends Comparable<E>> extends ObservableCollection<E, Set<E>> {

    public ObservableSet() {
        super(new HashSet<>());
    }
}
