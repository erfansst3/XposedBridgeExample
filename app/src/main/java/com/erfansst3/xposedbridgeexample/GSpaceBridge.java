package com.erfansst3.xposedbridgeexample;

/**
 * Small native bridge into the GSpace shared object already loaded in this process.
 *
 * resolve() only resolves an exported symbol address. It intentionally does not call
 * an unknown function: the exact ABI/signature must be known before a safe wrapper
 * can be implemented.
 */
public final class GSpaceBridge {
    static {
        System.loadLibrary("xposed_native_diag");
    }

    private GSpaceBridge() {}

    public static native String nativeReport();

    public static native long nativeResolve(String exportedSymbol);

    public static String report() {
        return nativeReport();
    }

    public static long resolve(String exportedSymbol) {
        return nativeResolve(exportedSymbol);
    }
}
