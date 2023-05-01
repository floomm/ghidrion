package view;

import javax.swing.JTextField;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.PlainDocument;

public class HexTextField extends JTextField {
	public HexTextField(int columns) {
		super("0x", columns);
        setDocument(new HexDocument());
    }

    private static class HexDocument extends PlainDocument {
        private static final String HEX_REGEX = "^0x[0-9a-fA-F]*$";
        private static final int MAX_LENGTH = 10; // maximum length of 0x followed by 8 hexadecimal digits

        @Override
        public void insertString(int offs, String str, AttributeSet a) throws BadLocationException {
            if (str == null) {
                return;
            }

            String currentText = getText(0, getLength());
            String newText = currentText.substring(0, offs) + str + currentText.substring(offs);
            if (isValidHex(newText)) {
                super.insertString(offs, str, a);
            }
        }

        private boolean isValidHex(String text) {
            return text.matches(HEX_REGEX) && text.length() <= MAX_LENGTH;
        }
    }
}
