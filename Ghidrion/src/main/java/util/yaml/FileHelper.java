package util.yaml;

import java.awt.Component;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import ui.ctrl.TraceFileNotFoundException;

/**
 * Provides utility methods for YAML file-related operations such as loading and
 * saving YAML files.
 */
public class FileHelper {

	/**
	 * Retrieves a FileInputStream of a YAML file selected by the user.
	 *
	 * @param parent the parent component used for displaying the file chooser
	 *               dialog
	 * @return a FileInputStream for the selected YAML file
	 * @throws TraceFileNotFoundException if the selected file is not found
	 */
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

	/**
	 * Displays a file chooser dialog for selecting a YAML file.
	 *
	 * @param parent the parent component used for displaying the file chooser
	 *               dialog
	 * @return the selected File object
	 * @throws TraceFileNotFoundException if the user cancels the file selection or
	 *                                    no file is selected
	 */
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

	/**
	 * Displays a file chooser dialog for saving respectively overriding a YAML
	 * file.
	 *
	 * @param parent the parent component used for displaying the file chooser
	 *               dialog
	 * @return the selected File object
	 * @throws TraceFileNotFoundException if the user cancels the file selection or
	 *                                    no file is selected
	 */
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
