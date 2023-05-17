package util;

public class YamlConverterException extends Exception {
	private final String title;
	private final String message;
	private final Throwable error;

	public YamlConverterException(String title, String message, Throwable error) {
		this.title = title;
		this.message = message;
		this.error = error;
	}
	
	public String getTitle() {
		return title;
	}
	
	public String getMessage() {
		return message;
	}
	
	public Throwable getError() {
		return error;
	}

}
