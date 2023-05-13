package ctrl;

import java.awt.Color;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.DefaultListModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import javax.swing.text.PlainDocument;
import javax.swing.text.DefaultHighlighter.DefaultHighlightPainter;

import util.ObservableList;

public class FilterPanelController<E> {
    private final Function<E, String> displayMapper;
    private final DefaultListModel<String> listModel;
    private final PlainDocument filterDocument;
    private final Highlighter filterHighlighter;
    private final List<E> inputElements = new ArrayList<>();
    private final ObservableList<E> outputList = new ObservableList<>();
    private final DefaultHighlightPainter highlighter = new DefaultHighlighter.DefaultHighlightPainter(
            Color.RED);
    private Object highlight = null;

    public FilterPanelController(Function<E, String> displayMapper, DefaultListModel<String> listModel,
            PlainDocument filterDocument, Highlighter filterHighlighter) {
        this.displayMapper = Objects.requireNonNull(displayMapper);
        this.listModel = Objects.requireNonNull(listModel);
        this.filterHighlighter = Objects.requireNonNull(filterHighlighter);
        this.filterDocument = Objects.requireNonNull(filterDocument);
        addFilterChangeListener();
    }

    private void addFilterChangeListener() {
        filterDocument.addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                filterChange();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                filterChange();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                filterChange();
            }
        });
    }

    private String getFilterText() {
        try {
            return filterDocument.getText(0, filterDocument.getLength());
        } catch (BadLocationException e) {
            e.printStackTrace();
            return "";
        }
    }

    private boolean isFilterValid() {
        try {
            Pattern.compile(getFilterText());
        } catch (PatternSyntaxException e) {
            return false;
        }
        return true;
    }

    private void filterChange() {
        boolean isFilterValid = isFilterValid();
        try {
            if (!isFilterValid)
                highlight = filterHighlighter.addHighlight(0, filterDocument.getLength(), highlighter);
            else if (highlight != null)
                filterHighlighter.removeHighlight(highlight);
        } catch (BadLocationException e) {
            e.printStackTrace();
        }

        if (isFilterValid) {
            updateDisplay();
            updateOutput();
        }
    }

    private boolean filterElement(E e) {
        return Pattern.compile(getFilterText()).matcher(displayMapper.apply(e)).find();
    }

    public void updateElements(Collection<E> elements) {
        inputElements.clear();
        inputElements.addAll(elements);
        updateDisplay();
        updateOutput();
    }

    public ObservableList<E> getOutputList() {
        return outputList;
    }

    public void addOutputObserver(Consumer<List<E>> observer) {
        outputList.addObserver(observer);
    }

    private void updateDisplay() {
        listModel.clear();
        listModel.addAll(inputElements
                .stream()
                .filter(this::filterElement)
                .map(displayMapper)
                .distinct()
                .sorted()
                .toList());
    }

    public void updateOutput() {
        updateOutput(List.of());
    }

    public void updateOutput(List<String> selectedValuesList) {
        outputList.clear();
        if (selectedValuesList.isEmpty())
            outputList.addAll(inputElements.stream().filter(this::filterElement).toList());
        else
            outputList.addAll(inputElements
                    .stream()
                    .filter(this::filterElement)
                    .filter(e -> selectedValuesList.contains(displayMapper.apply(e)))
                    .toList());
    }
}
