package ghidrion_scripts;

//Colors a recorded Morion trace in the Ghidra Listing window.
//@author Silvan Flum
//@category Morion
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import org.yaml.snakeyaml.Yaml;

import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;

public class MorionTraceColorizerScript extends GhidraScript {
	
	public void exec() throws Exception {
		run();
	}

	@Override
	protected void run() throws Exception {
        // Prompt the user to select a file
        File selectedFile = askFile("Select File", "OK");

        // Check if the user selected a file
        if (selectedFile == null) {
            Msg.info(this, "No file selected");
            return;
        }
        
        // Analyze the selected file
        analyzeFile(selectedFile);
        
        InputStream input = new FileInputStream(selectedFile);
        Yaml yaml = new Yaml();
        Object data = yaml.load(input);
	}
	
    private void analyzeFile(File file) {
        // Add your code here to analyze the selected file
        Msg.info(this, "Analyzing file: " + file.getAbsolutePath());
    }
    
}
