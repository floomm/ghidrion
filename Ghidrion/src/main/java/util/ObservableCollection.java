package util;

import java.util.Collection;
import java.util.Iterator;
import java.util.Objects;

public class ObservableCollection<E, C extends Collection<E>> extends Observable<C> implements Collection<E> {
    private final C collection;

    public ObservableCollection(C collection) {
        this.collection = Objects.requireNonNull(collection);
    }

    /**
     * @param e first gets removed if present and then re-added.
     * @return same value as {@link ObservableCollection#add(Object)}.
     */
    public boolean replace(E e) {
        collection.remove(e);
        return add(e);
    }

    /**
     * @param es first get removed if present and then re-added.
     * @return same value as {@link ObservableCollection#addAll(Collection)}.
     */
    public boolean replaceAll(Collection<E> es) {
        collection.removeAll(es);
        return addAll(es);
    }

    /**
     * @param newContent replaces all existing elements in the collection
     * @return same value as {@link ObservableCollection#addAll(Collection)}
     */
    public boolean replaceContent(Collection<E> newContent) {
        collection.clear();
        return addAll(newContent);
    }

    @Override
    public int size() {
        return collection.size();
    }

    @Override
    public boolean isEmpty() {
        return collection.isEmpty();
    }

    @Override
    public boolean contains(Object o) {
        return collection.contains(o);
    }

    @Override
    public Iterator<E> iterator() {
        Iterator<E> it = collection.iterator();
        return new Iterator<>() {
            @Override
            public boolean hasNext() {
                return it.hasNext();
            }

            @Override
            public E next() {
                return it.next();
            }
        };
    }

    @Override
    public Object[] toArray() {
        return collection.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a) {
        return collection.toArray(a);
    }

    @Override
    public boolean add(E e) {
        boolean r = collection.add(e);
        notifyObservers(collection);
        return r;
    }

    @Override
    public boolean remove(Object o) {
        boolean r = collection.remove(o);
        notifyObservers(collection);
        return r;
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return collection.containsAll(c);
    }

    @Override
    public boolean addAll(Collection<? extends E> c) {
        boolean r = collection.addAll(c);
        notifyObservers(collection);
        return r;
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        boolean r = collection.retainAll(c);
        notifyObservers(collection);
        return r;
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        boolean r = collection.removeAll(c);
        notifyObservers(collection);
        return r;
    }

    @Override
    public void clear() {
        collection.clear();
        notifyObservers(collection);
    }
}
