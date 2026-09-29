package com.erfansst3.xposedbridgeexample;

import java.lang.reflect.Method;

/**
 * Native API bridge for the SandHook runtime bundled inside GSpace.
 *
 * Important: this bridge intentionally does NOT initialize SandHook.
 * GSpace may already have initialized its native runtime, and calling
 * initNative() again from a guest/test class-loader is unsafe.
 */
public final class GSpaceBridge {
    static {
        System.loadLibrary("xposed_native_diag");
    }

    private GSpaceBridge() {}

    public static native String nativeReport();

    public static native long nativeResolve(String libraryName, String symbolName);

    public static native boolean nativeCanGetObject();

    public static native String nativeInspectSandHook();

    public static native String nativeDeepInspectSandHook();

    public static native int nativeHookMethod(
            Method origin,
            Method hook,
            Method backup,
            int hookMode);

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

    public static boolean canGetObject() {
        return nativeCanGetObject();
    }

    public static String inspectSandHook() {
        return nativeInspectSandHook();
    }

    public static String deepInspectSandHook() {
        return nativeDeepInspectSandHook();
    }

    /**
     * SandHook modes from the bundled SandHook implementation:
     * AUTO=0, INLINE=1, REPLACE=2.
     */
    public static int hookMethod(Method origin, Method hook, Method backup, int mode) {
        return nativeHookMethod(origin, hook, backup, mode);
    }
}
