package util;

import java.awt.Component;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import ctrl.TraceFileNotFoundException;

public class FileHelper {

	public static FileInputStream getFileStreamToLoad(Component parent) throws TraceFileNotFoundException {
		File file = chooseFile(parent);

		FileInputStream input;
		try {
			input = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			throw new TraceFileNotFoundException();
		}

		return input;
	}

	public static File chooseFile(Component parent) throws TraceFileNotFoundException {
		JFileChooser fileChooser = new JFileChooser();
		FileNameExtensionFilter filter = new FileNameExtensionFilter("YAML files", "yaml");
		fileChooser.setFileFilter(filter);
		int result = fileChooser.showOpenDialog(parent);
		if (result == JFileChooser.APPROVE_OPTION) {
			return fileChooser.getSelectedFile();
		}
		throw new TraceFileNotFoundException();
	}

	public static File saveFile(Component parent) throws TraceFileNotFoundException {
		JFileChooser fileChooser = new JFileChooser();
		FileNameExtensionFilter filter = new FileNameExtensionFilter("YAML files", "yaml");
		fileChooser.setFileFilter(filter);
		int result = fileChooser.showSaveDialog(parent);
		if (result == JFileChooser.APPROVE_OPTION) {
			return fileChooser.getSelectedFile();
		}
		throw new TraceFileNotFoundException();
	}

}
