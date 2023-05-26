package util;

import java.awt.Color;
import java.util.Objects;

/**
 * {@link util.Observable} {@link java.awt.Color}. Updates trigger on setting a
 * new color using {@link util.ObservableColor#setColor(Color)}.
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