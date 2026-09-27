package com.erfansst3.xposedbridgeexample;

import android.os.Bundle;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class XposedEntry implements IXposedHookLoadPackage{
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam p) throws Throwable{
        if(!p.packageName.equals("com.erfansst3.xposedbridgeexample"))return;
        MainActivity.xposedActive=true;
        MainActivity.xposedVersion=XposedBridge.getXposedVersion();
        XposedBridge.log("XposedBridgeExample: active");
        XposedHelpers.findAndHookMethod("com.erfansst3.xposedbridgeexample.MainActivity",p.classLoader,"onCreate",Bundle.class,new XC_MethodHook(){
            protected void beforeHookedMethod(MethodHookParam param){
                MainActivity.hooked=true;
                XposedBridge.log("XposedBridgeExample: hook SUCCESS");
            }
        });
    }
}