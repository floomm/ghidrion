package util;

import java.util.ArrayList;
import java.util.List;

public class ObservableList<E> extends ObservableCollection<E, List<E>> {
    public ObservableList() {
        super(new ArrayList<>());
    }
}
