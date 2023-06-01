package util.yaml;

import model.MorionInitTraceFile;
import model.MorionTraceFile;

/**
 * This exception is thrown when an error occurs during
 * YAML to @{@link MorionInitTraceFile} resp. {@link MorionTraceFile}
 * conversion.
 * It provides a title for categorizing the exception and an associated message
 * to describe the error.
 */
public class YamlConverterException extends Exception {
	private final String title;

	/**
	 * Constructs a YamlConverterException with the specified title and message.
	 *
	 * @param title   the title of the exception
	 * @param message the message describing the error
	 */
	public YamlConverterException(String title, String message) {
		super(message);
		this.title = title;
	}

	/**
	 * Constructs a YamlConverterException with the specified title, message, and
	 * underlying cause.
	 *
	 * @param title   the title of the exception
	 * @param message the message describing the error
	 * @param error   the underlying cause of the exception
	 */
	public YamlConverterException(String title, String message, Throwable error) {
		super(message, error);
		this.title = title;
	}

	public String getTitle() {
		return title;
	}

}
