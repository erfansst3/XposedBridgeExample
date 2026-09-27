package com.erfansst3.xposedbridgeexample;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity{
    static boolean hooked;
    public void onCreate(Bundle b){
        super.onCreate(b);
        TextView v=new TextView(this);
        v.setTextSize(18);
        StringBuilder s=new StringBuilder();
        s.append("XposedBridge: ").append(hasBridge()?"FOUND":"NOT FOUND").append("\n");
        s.append("Hook: ").append(hooked?"SUCCESS":"NOT EXECUTED").append("\n");
        s.append("Package: ").append(getPackageName()).append("\n");
        s.append("Process: ").append(android.os.Process.myPid());
        if(hasBridge()){
            try{s.append("\nXposed version: ").append(Class.forName("de.robv.android.xposed.XposedBridge").getMethod("getXposedVersion").invoke(null));}catch(Throwable e){s.append("\nVersion: ERROR");}
        }
        v.setText(s.toString());
        setContentView(v);
    }
    static boolean hasBridge(){
        try{Class.forName("de.robv.android.xposed.XposedBridge");return true;}catch(Throwable e){return false;}
    }
}
