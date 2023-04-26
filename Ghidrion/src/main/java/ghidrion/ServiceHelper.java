package ghidrion;

import java.awt.Component;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

public class ServiceHelper {

	public static <T> T getService(PluginTool tool, Class<T> c, Object originator, Component parent) {
		T service = tool.getService(c);
		if (service == null) {
			String name = c.getName();
			Msg.showError(originator, parent, "No " + name, "Can't find " + name);
		}
		
		return service;
	}

}
