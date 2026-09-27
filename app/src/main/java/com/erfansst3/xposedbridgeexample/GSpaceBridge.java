package com.erfansst3.xposedbridgeexample;

import android.os.Build;

import java.lang.reflect.Method;

/**
 * Native API bridge for the SandHook runtime bundled inside GSpace.
 */
public final class GSpaceBridge {
    static {
        System.loadLibrary("xposed_native_diag");
    }

    private GSpaceBridge() {}

    public static native String nativeReport();

    public static native long nativeResolve(String libraryName, String symbolName);

    public static native boolean nativeCanGetObject();

    public static native boolean nativeInitSandHook(int sdkInt, boolean debug);

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

    public static boolean initializeSandHook() {
        return nativeInitSandHook(Build.VERSION.SDK_INT, false);
    }

    public static boolean canGetObject() {
        return nativeCanGetObject();
    }

    /**
     * SandHook modes from the bundled SandHook implementation:
     * AUTO=0, INLINE=1, REPLACE=2.
     */
    public static int hookMethod(Method origin, Method hook, Method backup, int mode) {
        return nativeHookMethod(origin, hook, backup, mode);
    }
}
