package util;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

public class ObservableSet<E extends Comparable<E>> implements Observable<Set<E>> {

    private final Set<E> s = new HashSet<>();
    private final Set<Consumer<Set<E>>> observers = new HashSet<>();

    @Override
    public void addObserver(Consumer<Set<E>> observer) {
        observers.add(observer);
    }

    @Override
    public void removeObserver(Consumer<Set<E>> observer) {
        observers.remove(observer);
    }

    public void add(E e) {
        s.remove(e);
        s.add(e);
        notifyObservers();
    }

    public void addAll(Collection<E> es) {
        s.removeAll(es);
        s.addAll(es);
        notifyObservers();
    }

    public void remove(E e) {
        s.remove(e);
        notifyObservers();
    }

    public void removeAll(Collection<E> es) {
        s.removeAll(es);
        notifyObservers();
    }

    public void clear() {
        s.clear();
        notifyObservers();
    }

    public Set<E> getSet() {
        return new HashSet<>(s);
    }

    private void notifyObservers() {
        observers.forEach(observer -> observer.accept(new HashSet<>(s)));
    }
}
