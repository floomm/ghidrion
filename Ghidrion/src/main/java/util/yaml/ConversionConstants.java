package util.yaml;

import model.MorionInitTraceFile;
import model.MorionTraceFile;

/**
 * Provides constant values used for converting {@link MorionInitTraceFile}s
 * respectively {@link MorionTraceFile}s.
 * It contains string constants related to hooks, instructions, states, and
 * symbolic representation.
 */
public class ConversionConstants {
    public static final String HOOKS = "hooks";
    public static final String HOOK_ENTRY = "entry";
    public static final String HOOK_LEAVE = "leave";
    public static final String HOOK_TARGET = "target";
    public static final String HOOK_MODE = "mode";
    public static final String INFO = "info";
    public static final String INSTRUCTIONS = "instructions";
    public static final String STATES = "states";
    public static final String ENTRY_STATE = "entry";
    public static final String LEAVE_STATE = "leave";
    public static final String STATE_ADDRESS = "addr";
    public static final String STATE_MEMORY = "mems";
    public static final String STATE_REGISTERS = "regs";
    public static final String SYMBOLIC = "$$";
}
