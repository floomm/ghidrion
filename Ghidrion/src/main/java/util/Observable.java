package util;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Provides a wrapper for any element where objects can subscribe to changes.
 * What those changes are is left up to the implementation.
 */
public abstract class Observable<E> {
    private List<Consumer<E>> observers = new ArrayList<>();

    /**
     * @param observer triggered whenever the content changed
     * @return {@code true} as specified by {@link java.util.Collection#add(Object)}
     */
    public boolean addObserver(Consumer<E> observer) {
        return observers.add(observer);
    }

    public boolean removeObserver(Consumer<E> observer) {
        return observers.remove(observer);
    }

    /**
     * @param e the new value to be sent to all observers
     */
    protected void notifyObservers(E e) {
        observers.forEach(o -> o.accept(e));
    }
}
