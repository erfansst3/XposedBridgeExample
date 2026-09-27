package com.erfansst3.xposedbridgeexample;

/**
 * Native API discovery/bridge for the GSpace runtime libraries loaded in the guest.
 *
 * resolve() returns an exported symbol address only. Calling an arbitrary native
 * address is intentionally not exposed until its exact ABI/signature is known.
 */
public final class GSpaceBridge {
    static {
        System.loadLibrary("xposed_native_diag");
    }

    private GSpaceBridge() {}

    public static native String nativeReport();

    public static native long nativeResolve(String libraryName, String symbolName);

    public static String report() {
        return nativeReport();
    }

    public static long resolve(String libraryName, String symbolName) {
        return nativeResolve(libraryName, symbolName);
    }

    public static long resolveStub(String symbolName) {
        return nativeResolve("libstub.so", symbolName);
    }

    public static long resolveGSpace(String symbolName) {
        return nativeResolve("libgspace_64.so", symbolName);
    }
}
