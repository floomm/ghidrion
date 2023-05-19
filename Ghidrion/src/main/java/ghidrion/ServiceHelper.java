package ghidrion;

import java.awt.Component;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

// TODO: Why is this even a thing?
public class ServiceHelper {

	/**
	 * Returns the Ghidra service object that implements the given service interface.
	 * 
	 * @param <T>
	 * @param tool contains the service object
	 * @param c the interface class
	 * @param originator a Logger instance, "this", or YourClass.class
	 * @param parent a component (or null if you don't have one) used to center a possible error dialog
	 * @return service object
	 */
	public static <T> T getService(PluginTool tool, Class<T> c, Object originator, Component parent) {
		T service = tool.getService(c);
		if (service == null) {
			String name = c.getName();
			Msg.showError(originator, parent, "No " + name, "Can't find " + name);
		}
		
		return service;
	}

}
