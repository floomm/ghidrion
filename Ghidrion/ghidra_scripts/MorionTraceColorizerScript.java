/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// An example of how to color the listing background 
//@category Examples

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.util.Msg;

import java.awt.Color;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.yaml.snakeyaml.Yaml;

public class MorionTraceColorizerScript extends GhidraScript {
	
	private static final int BASE_ADDRESS = 0x00400000;
	private static final String INSTRUCTIONS_KEY = "instructions";
	private static final Color TRACE_COLOR = Color.CYAN;

	@Override
	public void run() throws Exception {
		ColorizingService service = state.getTool().getService(ColorizingService.class);
		if (service == null) {
			println("Can't find ColorizingService service");
			return;
		}

		// Set base address
		if (currentProgram.getImageBase().getOffset() != BASE_ADDRESS) {
			Address baseAddress = toAddr(BASE_ADDRESS);
			currentProgram.setImageBase(baseAddress, getReusePreviousChoices());
		}

        // Prompt the user to select a file
        File traceFile = askFile("Select File", "OK");

        // Check if the user selected a file
        if (traceFile == null) {
            Msg.info(this, "No file selected");
            return;
        }
        
        InputStream input = new FileInputStream(traceFile);
        Yaml yaml = new Yaml();
        Map<String, Collection> trace = (LinkedHashMap<String, Collection>) yaml.load(input);
        ArrayList<ArrayList<String>> instructions = (ArrayList<ArrayList<String>>) trace.get(INSTRUCTIONS_KEY);
        ArrayList<String> tracedAddresses = instructions.stream()
        		.filter(instruction -> !instruction.isEmpty())
        		.map(instruction -> instruction.get(0))
        		.map(address -> address.substring(2))
        		.collect(Collectors.toCollection(ArrayList::new));
        AddressSet addresses = new AddressSet();
        for (String address : tracedAddresses) {
        	addresses.add(parseAddress(address));
        }
        
        service.setBackgroundColor(addresses, TRACE_COLOR);
		
	}

}
