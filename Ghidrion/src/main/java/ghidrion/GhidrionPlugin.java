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
package ghidrion;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.DecompilerHighlightService;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraState;
import ghidra.app.services.GhidraScriptService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import view.GhidrionProvider;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here.",
	servicesRequired = { GhidraScriptService.class }
)
//@formatter:on
public class GhidrionPlugin extends ProgramPlugin {

	// Scripts
	public final TraceColorizerScript colorizerScript = new TraceColorizerScript(this);
	public final JumpToAddressScript jumpToAddressScript = new JumpToAddressScript();

	// Services
	private ColorizingService colorizingService;
	private DecompilerHighlightService decompilerHighlightService;

	private GhidrionProvider provider;
	private FlatProgramAPI flatAPI;

	private final List<Consumer<Program>> programOpenedListeners = new ArrayList<>();

	private static final String PLUGIN_NAME = "Ghidrion";

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidrionPlugin(PluginTool tool) {
		super(tool);
		GhidraState state = new GhidraState(tool, tool.getProject(), currentProgram, currentLocation, currentSelection,
				currentHighlight);
		colorizerScript.set(new GhidraState(state), null, null);
		jumpToAddressScript.set(new GhidraState(state), null, null);

		String owner = getName();

		provider = new GhidrionProvider(this, PLUGIN_NAME, owner);

		if (currentProgram != null) {
			this.flatAPI = new FlatProgramAPI(currentProgram);
		}
	}

	@Override
	public void init() {
		super.init();

		// Acquire services here
		colorizingService = ServiceHelper.getService(tool, ColorizingService.class, this, provider.getComponent());
		decompilerHighlightService = ServiceHelper.getService(tool, DecompilerHighlightService.class, this,
				provider.getComponent());
	}

	@Override
	protected void programActivated(Program program) {
		currentProgram = program;
		flatAPI = new FlatProgramAPI(program);

		// Set state of scripts
		GhidraState state = new GhidraState(tool, tool.getProject(), program, currentLocation, currentSelection,
				currentHighlight);
		colorizerScript.set(state, null, null);
		jumpToAddressScript.set(state, null, null);

		super.programActivated(program);
	}

	@Override
	protected void programOpened(Program program) {
		programOpenedListeners.forEach(l -> l.accept(program));
		super.programOpened(program);
	}

	public void addProgramOpenendListener(Consumer<Program> listener) {
		programOpenedListeners.add(listener);
	}

	public void removeProgramOpenendListener(Consumer<Program> listener) {
		programOpenedListeners.remove(listener);
	}

	public ColorizingService getColorizingService() {
		return colorizingService;
	}

	public DecompilerHighlightService getDecompilerHighlightService() {
		return decompilerHighlightService;
	}

	public FlatProgramAPI getFlatAPI() {
		return flatAPI;
	}
}
