package view;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JPanel;

import org.yaml.snakeyaml.Yaml;

import model.MorionTraceFile;

public class CreateTraceFilePanel extends JPanel {
	
	private MorionTraceFile traceFile = new MorionTraceFile();
	
	private HooksPanel hooksPanel = new HooksPanel(this);
	private StatesPanel statesPanel = new StatesPanel(this);

	public CreateTraceFilePanel() {
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		
		JButton createButton = new JButton("Create Morion trace file");
		createButton.addActionListener(e -> {
			File file = new File("tracefile.init.yaml");
			Yaml yaml = new Yaml();
			String content = yaml.dump(traceFile.getTraceFile());
			
			JFileChooser fileChooser = new JFileChooser();
			int result = fileChooser.showSaveDialog(this.getParent());
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
		});

		add(hooksPanel);
		add(statesPanel);
		add(createButton);
	}
	
	public void init() {
		// TODO
	}
	
	public void addHook(String libraryName, String functionName, String entryAddress, String leaveAddress, String targetAddress, String mode) {
		traceFile.addHook(libraryName, functionName, entryAddress, leaveAddress, targetAddress, mode);
	}
	
	public void addEntryStateRegister(String name, String value, boolean isSymbolic) {
		traceFile.addEntryRegister(name, value, isSymbolic);
	}
	
	public void addEntryStateMemory(String address, String value, boolean isSymbolic) {
		traceFile.addEntryMemory(address, value, isSymbolic);
	}

}
