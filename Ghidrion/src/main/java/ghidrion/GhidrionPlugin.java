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
import ghidra.program.model.listing.Program;
import model.MorionInitTraceFile;
import util.TraceColorizerScript;
import view.GhidrionProvider;

/**
 * This plugin allows a user to leverage the power of Ghidra to create and
 * analyze Morion traces. It has two parts:
 * 
 * First, it allows a user to create init hook files. These can then be used to
 * create traces in Morion. They contain hooked functions and initial memory and
 * register values.
 * 
 * Second, it allows a user to analyze a trace by analyzing the visited
 * addresses in Ghidra's listing view and quickly finding differences in memory
 * and registers created during the tracing.
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

	// Services
	private ColorizingService colorizingService;
	private DecompilerHighlightService decompilerHighlightService;

	private GhidrionProvider provider;

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

		String owner = getName();

		MorionInitTraceFile traceFile = new MorionInitTraceFile();
		addProgramOpenendListener(p -> traceFile.clear()); // clear trace when a new program is loaded

		provider = new GhidrionProvider(this, PLUGIN_NAME, owner, traceFile);
		new GhidrionHookAddingListingContextAction(this, traceFile);
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

		// Set state of scripts
		GhidraState state = new GhidraState(tool, tool.getProject(), program, currentLocation, currentSelection,
				currentHighlight);
		colorizerScript.set(state, null, null);

		super.programActivated(program);
	}

	@Override
	protected void programOpened(Program program) {
		programOpenedListeners.forEach(l -> l.accept(program));
		super.programOpened(program);
	}

	/**
	 * @param listener gets triggered when a program is opened (according to
	 *                 {@link ghidra.app.plugin.ProgramPlugin#programOpened}).
	 */
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
}
