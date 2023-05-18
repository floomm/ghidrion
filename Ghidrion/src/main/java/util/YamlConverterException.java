package util;

public class YamlConverterException extends Exception {
	private final String title;
	
	public YamlConverterException(String title, String message) {
		super(message);
		this.title = title;
	}
	
	public YamlConverterException(String title, String message, Throwable error) {
		super(message, error);
		this.title = title;
	}
	
	public String getTitle() {
		return title;
	}

}
