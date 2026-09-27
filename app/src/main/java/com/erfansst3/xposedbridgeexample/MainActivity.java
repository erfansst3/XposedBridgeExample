package com.erfansst3.xposedbridgeexample;

import android.app.Activity;
import android.os.Bundle;
import android.os.Debug;
import android.os.Process;
import android.content.pm.ApplicationInfo;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.FileReader;

public class MainActivity extends Activity{
    static volatile boolean hooked;
    static volatile int xposedVersion;
    static volatile boolean mark;
    public static void markHooked(){hooked=true;mark=true;}
    public static void setVersion(int v){xposedVersion=v;}
    static String probe(String n,ClassLoader... ls){
        for(ClassLoader l:ls)try{if(l!=null)Class.forName(n,false,l);else Class.forName(n);return "YES";}catch(Throwable e){}
        return "NO";
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
    static String pkg(String n){
        try{getApp().getPackageManager().getApplicationInfo(n,0);return "YES";}catch(Throwable e){return "NO";}
    }
    static MainActivity getApp(){return holder;}
    static MainActivity holder;
    static String maps(){
        StringBuilder s=new StringBuilder();
        try{
            BufferedReader r=new BufferedReader(new FileReader("/proc/self/maps"));
            String x;
            while((x=r.readLine())!=null){
                String y=x.toLowerCase();
                if(y.contains("sandhook")||y.contains("xposed")||y.contains("virtualapp")||y.contains("libva")||y.contains("vxp"))s.append(x).append("\n");
            }
            r.close();
        }catch(Throwable e){return e.getClass().getSimpleName();}
        return s.length()==0?"NONE":s.toString();
    }
    public void onCreate(Bundle b){
        super.onCreate(b);
        holder=this;
        ClassLoader app=getClassLoader(),ctx=getApplicationContext().getClassLoader(),tc=Thread.currentThread().getContextClassLoader(),sys=ClassLoader.getSystemClassLoader();
        boolean dbg=(getApplicationInfo().flags&ApplicationInfo.FLAG_DEBUGGABLE)!=0;
        TextView v=new TextView(this);
        v.setTextSize(15);
        v.setText("Xposed callback: "+(hooked?"YES":"NO")+
                "\nGuest hook state: "+(mark?"YES":"NO")+
                "\nXposedBridge: "+probe("de.robv.android.xposed.XposedBridge",app,ctx,tc,sys,null)+
                "\nXposedCompat: "+probe("com.swift.sandhook.xposedcompat.XposedCompat",app,ctx,tc,sys,null)+
                "\nSandHook: "+probe("com.swift.sandhook.SandHook",app,ctx,tc,sys,null)+
                "\nVirtualCore: "+probe("com.lody.virtual.client.core.VirtualCore",app,ctx,tc,sys,null)+
                "\nDebuggable: "+dbg+
                "\nvxp props: "+prop("vxp")+"/"+prop("sandvxp")+
                "\nHost package visible: io.virtualapp.sandvxposed="+pkg("io.virtualapp.sandvxposed")+
                "\nUID/PID: "+Process.myUid()+"/"+Process.myPid()+
                "\nData: "+getApplicationInfo().dataDir+
                "\nSource: "+getApplicationInfo().sourceDir+
                "\nClassLoader: "+cls(app)+
                "\n\n/proc/self/maps:\n"+maps());
        setContentView(v);
    }
}