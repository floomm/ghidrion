package util;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class ObservableSet<E extends Comparable<E>> extends Observable<Set<E>> implements Set<E> {
    private final Set<E> s = new HashSet<>();

    @Override
    public int size() {
        return s.size();
    }

    @Override
    public boolean isEmpty() {
        return s.isEmpty();
    }

    @Override
    public boolean contains(Object o) {
        return s.contains(o);
    }

    @Override
    public Iterator<E> iterator() {
        Iterator<E> sI = s.iterator();
        return new Iterator<>() {
            @Override
            public boolean hasNext() {
                return sI.hasNext();
            }

            @Override
            public E next() {
                return sI.next();
            }
        };
    }

    @Override
    public Object[] toArray() {
        return s.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a) {
        return s.toArray(a);
    }

    @Override
    public boolean add(E e) {
        boolean r = s.add(e);
        notifyObservers(s);
        return r;
    }

    @Override
    public boolean remove(Object o) {
        boolean r = s.remove(o);
        notifyObservers(s);
        return r;
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return s.containsAll(c);
    }

    @Override
    public boolean addAll(Collection<? extends E> c) {
        boolean r = s.addAll(c);
        notifyObservers(s);
        return r;
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        boolean r = s.retainAll(c);
        notifyObservers(s);
        return r;
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        boolean r = s.removeAll(c);
        notifyObservers(s);
        return r;
    }

    @Override
    public void clear() {
        s.clear();
        notifyObservers(s);
    }
}
