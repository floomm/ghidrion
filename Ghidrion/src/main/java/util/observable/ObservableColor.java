package util.observable;

import java.awt.Color;
import java.util.Objects;

/**
 * {@link util.observable.Observable} {@link java.awt.Color}. Updates trigger on
 * setting a
 * new color using {@link util.observable.ObservableColor#setColor(Color)}.
 */
public class ObservableColor extends Observable<Color> {
    private Color c;

    public ObservableColor(Color initialColor) {
        this.c = Objects.requireNonNull(initialColor);
    }

    public void setColor(Color c) {
        this.c = Objects.requireNonNull(c);
        super.notifyObservers(c);
    }

    public Color getColor() {
        return c;
    }
}