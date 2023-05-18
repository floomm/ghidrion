package ghidrion;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

public class JumpToAddressScript extends GhidraScript {
	
	@Override
	protected void run() throws Exception {
	}
	
	protected void run(Address address) {
		if (address != null) {
			goTo(address);
			Msg.info(this, "Jumped to address " + address.toString());
		}
	}

}
