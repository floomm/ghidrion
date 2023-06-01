package util.observable;

import java.util.HashSet;
import java.util.Set;

/**
 * {@link util.observable.Observable} {@link java.util.Set}. Uses the
 * {@link java.util.HashSet} implementation internally.
 */
public class ObservableSet<E extends Comparable<E>> extends ObservableCollection<E, Set<E>> {
    public ObservableSet() {
        super(new HashSet<>());
    }
}
