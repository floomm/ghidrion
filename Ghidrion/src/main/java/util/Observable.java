package util;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class Observable<E> {
    private List<Consumer<E>> observers = new ArrayList<>();

    public boolean addObserver(Consumer<E> observer) {
        return observers.add(observer);
    }

    public boolean removeObserver(Consumer<E> observer) {
        return observers.remove(observer);
    }

    protected void notifyObservers(E e) {
        observers.forEach(o -> o.accept(e));
    }
}
