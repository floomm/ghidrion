package ctrl;

import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.swing.JFileChooser;

import org.yaml.snakeyaml.Yaml;

import ghidrion.GhidrionPlugin;
import ghidrion.MorionTraceColorizer;
import model.MorionTraceFile;

public class TraceFileController {
	private MorionTraceFile traceFile = new MorionTraceFile();
	private MorionTraceColorizer colorizer;
	
	public TraceFileController(GhidrionPlugin plugin) {
		this.colorizer = new MorionTraceColorizer(plugin);
	}
	
	public MorionTraceColorizer getColorizer() {
		return colorizer;
	}
	
	public String getSymbolicMarker() {
		return MorionTraceFile.SYMBOLIC;
	}
	
	public void addHook(String libraryName, String functionName, String entry, String leave, String target, String mode) {
		traceFile.addHook(libraryName, functionName, entry, leave, target, mode);
	}

	public void addEntryStateRegister(String name, String value, boolean isSymbolic) {
		traceFile.addEntryStateRegister(name, value, isSymbolic);
	}

	public void addEntryStateMemory(String address, String value, boolean isSymbolic) {
		traceFile.addEntryStateMemory(address, value, isSymbolic);
	}
	
	public void createTraceFile(Component container) {
		Yaml yaml = new Yaml();
		String content = yaml.dump(traceFile.getTraceFile());
		
		JFileChooser fileChooser = new JFileChooser();
		int result = fileChooser.showSaveDialog(container);
		File file = null;
		if (result == JFileChooser.APPROVE_OPTION) {
			file = fileChooser.getSelectedFile();
		}
		
		if (file != null) {
			try (FileOutputStream fos = new FileOutputStream(file)) {
				fos.write(content.getBytes());
				fos.close();
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		}
	}
}
