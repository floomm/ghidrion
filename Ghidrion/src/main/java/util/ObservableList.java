package util;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link util.Observable} {@link java.util.List}. Uses the
 * {@link java.util.ArrayList} implementation internally.
 */
public class ObservableList<E> extends ObservableCollection<E, List<E>> {
    public ObservableList() {
        super(new ArrayList<>());
    }
}
