package view;

import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.PlainDocument;

public class HexDocument extends PlainDocument {
	public static final int MAX_HEX_DIGITS_MEMORY_ADDRESS = 8;
	public static final int MAX_HEX_DIGITS_REGISTER_VALUE = 8;
	public static final int MAX_HEX_DIGITS_UNLIMITED = -1;

	private static final String HEX_REGEX = "[0-9a-fA-F]+";

	private final int maxHexDigits;

	public HexDocument(int maxHexDigits) {
		this.maxHexDigits = maxHexDigits;
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
			super.insertString(offs, str.toLowerCase(), a);
			if (maxHexDigits == MAX_HEX_DIGITS_UNLIMITED || getLength() > maxHexDigits + 2)
				super.remove(maxHexDigits, getLength() - (maxHexDigits + 2));
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
		return text.startsWith("0x") && text.substring(2).matches(HEX_REGEX);
	}

}
