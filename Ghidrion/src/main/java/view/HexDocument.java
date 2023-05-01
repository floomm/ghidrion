package view;

import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.PlainDocument;

public class HexDocument extends PlainDocument {
	private static final String HEX_REGEX = "[0-9a-fA-F]+";
	private static final int MAX_LENGTH = 10; // maximum length of 0x followed by 8 hexadecimal digits

	public HexDocument() {
		try {
			super.insertString(0, "0x", null);
		} catch (BadLocationException e) {
			e.printStackTrace();
		}
	}
	
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
	
	@Override
	public void remove(int offs, int len) throws BadLocationException {
		if (offs == 0 || offs == 1) {
			return;
		}
		super.remove(offs, len);
	}
	
	private boolean isValidHex(String text) {
	    return text.startsWith("0x") && text.substring(2).matches(HEX_REGEX) && text.length() <= MAX_LENGTH;
	}

}
