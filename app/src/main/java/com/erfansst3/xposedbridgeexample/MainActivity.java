package com.erfansst3.xposedbridgeexample;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity{
    static volatile boolean hooked;
    static volatile int xposedVersion;
    static volatile boolean mark;
    public static void markHooked(){hooked=true;mark=true;}\n    public static void setVersion(int v){xposedVersion=v;}
    static String probe(String n,ClassLoader l){
        try{Class.forName(n,false,l);return "YES";}catch(Throwable e){return "NO";}
    }
    static String prop(String n){try{return System.getProperty(n,"-");}catch(Throwable e){return "ERR";}}
    static String cls(ClassLoader l){
        StringBuilder s=new StringBuilder();
        for(int i=0;l!=null&&i<8;i++,l=l.getParent()){
            if(i>0)s.append(" <- ");
            s.append(l.getClass().getName());
        }
        return s.toString();
    }
    public void onCreate(Bundle b){
        super.onCreate(b);
        ClassLoader l=getClassLoader();
        TextView v=new TextView(this);
        v.setTextSize(16);
        v.setText("Hook callback: "+(hooked?"YES":"NO")+
                "\nHook state in app ClassLoader: "+(mark?"YES":"NO")+
                "\nXposedBridge: "+probe("de.robv.android.xposed.XposedBridge",l)+
                "\nSandHook: "+probe("com.swift.sandhook.SandHook",l)+
                "\nXposedCompat: "+probe("com.swift.sandhook.xposedcompat.XposedCompat",l)+
                "\nvxp: "+prop("vxp")+"  sandvxp: "+prop("sandvxp")+
                "\nVersion: "+(xposedVersion==0?"UNKNOWN":xposedVersion)+
                "\nPackage: "+getPackageName()+
                "\n\nClassLoader:\n"+cls(l));
        setContentView(v);
    }
}