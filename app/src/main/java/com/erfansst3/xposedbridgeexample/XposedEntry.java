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
        try{
            Class<?> c=Class.forName(p.packageName+".MainActivity",true,p.classLoader);
            XposedHelpers.callStaticMethod(c,"markHooked");
            XposedBridge.log("XposedBridgeExample: target class marked");
        }catch(Throwable t){XposedBridge.log("XposedBridgeExample: mark failed "+t);}
        XposedHelpers.findAndHookMethod(p.packageName+".MainActivity",p.classLoader,"onCreate",Bundle.class,new XC_MethodHook(){
            protected void beforeHookedMethod(MethodHookParam param){
                try{XposedHelpers.callStaticMethod(param.thisObject.getClass(),"markHooked");}catch(Throwable ignored){}
                try{XposedHelpers.callStaticMethod(param.thisObject.getClass(),"setVersion",XposedBridge.getXposedVersion());}catch(Throwable ignored){}
                XposedBridge.log("XposedBridgeExample: hook SUCCESS");
            }
        });
    }
}