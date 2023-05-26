package util;

import java.util.HashSet;
import java.util.Set;

/**
 * {@link util.Observable} {@link java.util.Set}. Uses the
 * {@link java.util.HashSet} implementation internally.
 */
public class ObservableSet<E extends Comparable<E>> extends ObservableCollection<E, Set<E>> {
    public ObservableSet() {
        super(new HashSet<>());
    }
}
