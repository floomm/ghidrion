package ghidrion;

import ghidra.framework.plugintool.PluginTool;

public class ServiceHelper {

	public static <T> T getService(PluginTool tool, Class<T> c) {
		T service = tool.getService(c);
		if (service == null) {
			// Handle the case where the service is not available
            throw new RuntimeException(c.getName() + " not found");
		}
		
		return service;
	}

}
