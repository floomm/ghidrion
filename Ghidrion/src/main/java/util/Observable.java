package util;

import java.util.function.Consumer;

public interface Observable<E> {
    void addObserver(Consumer<E> observer);

    void removeObserver(Consumer<E> observer);
}
