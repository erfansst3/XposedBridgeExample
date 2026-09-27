package com.erfansst3.xposedbridgeexample;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity{
    static volatile boolean xposedActive,hooked;
    static volatile int xposedVersion;
    public void onCreate(Bundle b){
        super.onCreate(b);
        TextView v=new TextView(this);
        v.setTextSize(18);
        v.setText("Xposed: "+(xposedActive?"ACTIVE":"NOT ACTIVE")+
                "\nHook: "+(hooked?"SUCCESS":"NOT EXECUTED")+
                "\nVersion: "+(xposedVersion==0?"UNKNOWN":xposedVersion)+
                "\nPackage: "+getPackageName()+
                "\nProcess: "+android.os.Process.myPid());
        setContentView(v);
    }
}