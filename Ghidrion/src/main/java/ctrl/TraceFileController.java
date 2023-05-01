package ctrl;

import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
		Map<String, String> hookDetails = new HashMap<>();
		hookDetails.put("entry", entry);
		hookDetails.put("leave", leave);
		hookDetails.put("target", target);
		hookDetails.put("mode", mode);
		
		traceFile.addHook(libraryName, functionName, hookDetails);
	}

	public void addEntryStateRegister(String name, String value, boolean isSymbolic) {
		List<String> valueList = new ArrayList<>();
		valueList.add(value);
		if (isSymbolic) {
			valueList.add(MorionTraceFile.SYMBOLIC);
		}
		traceFile.addEntryStateRegister(name, valueList);
	}

	public void addEntryStateMemory(String address, String value, boolean isSymbolic) {
		List<String> valueList = new ArrayList<>();
		valueList.add(value);
		if (isSymbolic) {
			valueList.add(MorionTraceFile.SYMBOLIC);
		}
		traceFile.addEntryStateMemory(address, valueList);
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
