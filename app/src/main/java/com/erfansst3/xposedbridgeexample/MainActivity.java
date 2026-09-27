package com.erfansst3.xposedbridgeexample;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
    static volatile boolean hooked;
    static volatile boolean mark;

    static {
        System.loadLibrary("xposed_native_diag");
    }

    public static void markHooked() { hooked = true; mark = true; }

    static String probe(String n, ClassLoader... ls) {
        for (ClassLoader l : ls) {
            try {
                if (l != null) Class.forName(n, false, l);
                else Class.forName(n);
                return "YES";
            } catch (Throwable ignored) {}
        }
        return "NO";
    }

    private static native String nativeDiagnostics();

    @Override
    public void onCreate(Bundle b) {
        super.onCreate(b);

        ClassLoader app = getClassLoader();
        ClassLoader ctx = getApplicationContext().getClassLoader();
        ClassLoader tc = Thread.currentThread().getContextClassLoader();

        StringBuilder s = new StringBuilder();
        s.append("Xposed callback: ").append(hooked ? "YES" : "NO").append('\n');
        s.append("Guest hook state: ").append(mark ? "YES" : "NO").append('\n');
        s.append("XposedBridge: ")
                .append(probe("de.robv.android.xposed.XposedBridge", app, ctx, tc, null)).append('\n');
        s.append("XposedCompat: ")
                .append(probe("com.swift.sandhook.xposedcompat.XposedCompat", app, ctx, tc, null)).append('\n');
        s.append("SandHook: ")
                .append(probe("com.swift.sandhook.SandHook", app, ctx, tc, null)).append('\n');
        s.append("VirtualCore: ")
                .append(probe("com.lody.virtual.client.core.VirtualCore", app, ctx, tc, null)).append('\n');

        String data = getApplicationInfo().dataDir;
        boolean virtualData = data.contains("/virtual/") || data.contains("/gspace/") ||
                data.contains("com.gspace.android") || data.contains("virtualapp");
        s.append("Virtual data-path marker: ").append(virtualData ? "YES" : "NO").append('\n');
        s.append("Data: ").append(data).append('\n');

        s.append("\n=== NATIVE RELATED CHECKS ===\n");
        try {
            s.append(nativeDiagnostics());
        } catch (Throwable t) {
            s.append("Native diagnostics failed: ").append(t.getClass().getSimpleName())
                    .append(": ").append(t.getMessage()).append('\n');
        }

        TextView v = new TextView(this);
        v.setTextSize(14);
        v.setText(s.toString());
        setContentView(v);
    }
}
