package com.erfansst3.xposedbridgeexample;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.Button;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;

import java.lang.reflect.Method;

public class MainActivity extends Activity {
    static volatile boolean hooked;
    static volatile boolean mark;

    static {
        System.loadLibrary("xposed_native_diag");
    }

    public static void markHooked() {
        hooked = true;
        mark = true;
    }

    public static class HookTarget {
        public static String value() {
            return "ORIGINAL";
        }
    }

    public static class HookReplacement {
        public static String value() {
            markHooked();
            return "HOOKED_BY_GSPACE_SANDHOOK";
        }
    }

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

    private String runJavaSandHookClassInspector() {
        StringBuilder out = new StringBuilder();
        out.append("=== JAVA SANDHOOK CLASSLOADER INSPECTOR ===\\n");

        ClassLoader app = getClassLoader();
        ClassLoader ctx = getApplicationContext().getClassLoader();
        ClassLoader tc = Thread.currentThread().getContextClassLoader();
        ClassLoader sys = ClassLoader.getSystemClassLoader();

        ClassLoader[] loaders = {app, ctx, tc, sys, null};
        String[] labels = {"Activity", "Application", "ThreadContext", "System", "Default"};

        for (int i = 0; i < loaders.length; i++) {
            try {
                ClassLoader loader = loaders[i];
                Class<?> c;
                if (loader != null) {
                    c = Class.forName("com.swift.sandhook.SandHook", false, loader);
                } else {
                    c = Class.forName("com.swift.sandhook.SandHook");
                }

                out.append(labels[i]).append(": FOUND");
                out.append(" classLoader=").append(String.valueOf(c.getClassLoader()));
                out.append(" methods=").append(c.getDeclaredMethods().length);
                out.append(" fields=").append(c.getDeclaredFields().length);
                out.append("\\n");
            } catch (Throwable t) {
                out.append(labels[i]).append(": NOT FOUND (")
                        .append(t.getClass().getSimpleName())
                        .append(": ").append(String.valueOf(t.getMessage()))
                        .append(")\\n");
            }
        }

        return out.toString();
    }

    private String runSandHookTest() {
        StringBuilder out = new StringBuilder();
        out.append("=== EXISTING GSPACE SANDHOOK STATE ===\n");

        try {
            long canGetAddress = GSpaceBridge.resolveGSpace(
                    "Java_com_swift_sandhook_SandHook_canGetObject");
            long hookAddress = GSpaceBridge.resolveGSpace(
                    "Java_com_swift_sandhook_SandHook_hookMethod");
            long initAddress = GSpaceBridge.resolveGSpace(
                    "Java_com_swift_sandhook_SandHook_initNative");

            out.append("libgspace_64.so SandHook.canGetObject: 0x")
                    .append(Long.toHexString(canGetAddress)).append('\n');
            out.append("libgspace_64.so SandHook.hookMethod: 0x")
                    .append(Long.toHexString(hookAddress)).append('\n');
            out.append("libgspace_64.so SandHook.initNative: 0x")
                    .append(Long.toHexString(initAddress)).append('\n');
            out.append("IMPORTANT: initNative is NOT called.\n");

            boolean canGetObject = GSpaceBridge.canGetObject();
            out.append("Existing native state canGetObject(): ")
                    .append(canGetObject ? "YES" : "NO").append('\n');

            Method origin = HookTarget.class.getDeclaredMethod("value");
            Method replacement = HookReplacement.class.getDeclaredMethod("value");

            String before = HookTarget.value();
            out.append("Before hook: ").append(before).append('\n');

            if (!canGetObject) {
                out.append("RESULT: NOT RUN — existing SandHook native state is not ready.\n");
                out.append("This test deliberately avoids re-initializing GSpace SandHook.\n");
                return out.toString();
            }

            if (hookAddress == 0L) {
                out.append("RESULT: NOT RUN — hookMethod export not found.\n");
                return out.toString();
            }

            int result = GSpaceBridge.hookMethod(origin, replacement, null, 2);
            out.append("SandHook.hookMethod(mode=REPLACE): ")
                    .append(result).append('\n');

            String after = HookTarget.value();
            out.append("After hook: ").append(after).append('\n');
            out.append("Hook callback flag: ").append(hooked ? "YES" : "NO").append('\n');

            if ("HOOKED_BY_GSPACE_SANDHOOK".equals(after)) {
                out.append("RESULT: HOOK SUCCESS\n");
            } else {
                out.append("RESULT: HOOK DID NOT TAKE EFFECT\n");
            }
        } catch (Throwable t) {
            out.append("RESULT: EXCEPTION\n")
                    .append(t.getClass().getName())
                    .append(": ").append(String.valueOf(t.getMessage())).append('\n');
        }

        return out.toString();
    }

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

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setVerticalScrollBarEnabled(true);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 24, 24, 24);

        TextView resultView = new TextView(this);
        resultView.setTextSize(13);
        resultView.setTextIsSelectable(true);

        Button inspect = new Button(this);
        inspect.setText("RUN SANDHOOK DEEP INSPECTOR");
        inspect.setOnClickListener(view -> resultView.setText(
                GSpaceBridge.deepInspectSandHook() + "\n\n" + runJavaSandHookClassInspector()));
        root.addView(inspect, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        Button trace = new Button(this);
        trace.setText("RUN LOADER TRACE");
        trace.setOnClickListener(view -> resultView.setText(GSpaceBridge.traceLoader()));
        root.addView(trace, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        Button test = new Button(this);
        test.setText("RUN LIVE SANDHOOK TEST");
        test.setOnClickListener(view -> resultView.setText(runSandHookTest()));
        root.addView(test, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        Button copyTest = new Button(this);
        copyTest.setText("COPY TEST RESULT");
        copyTest.setOnClickListener(view -> {
            ClipboardManager cm =
                    (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText(
                        "SandHook test",
                        resultView.getText().toString()));
                copyTest.setText("COPIED");
                copyTest.postDelayed(() -> copyTest.setText("COPY TEST RESULT"), 1200);
            }
        });
        root.addView(copyTest, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        Button copy = new Button(this);
        copy.setText("COPY FULL REPORT");
        final String report = s.toString();
        copy.setOnClickListener(view -> {
            ClipboardManager cm =
                    (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText(
                        "XposedBridgeExample report", report));
                copy.setText("COPIED");
                copy.postDelayed(() -> copy.setText("COPY FULL REPORT"), 1200);
            }
        });
        root.addView(copy, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        TextView v = new TextView(this);
        v.setTextSize(12);
        v.setTextIsSelectable(true);
        v.setText(report);
        v.setGravity(android.view.Gravity.TOP | android.view.Gravity.START);
        root.addView(v, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        root.addView(resultView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        scroll.addView(root);
        setContentView(scroll);
    }
}
