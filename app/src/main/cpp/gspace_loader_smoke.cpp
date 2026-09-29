#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <atomic>
#include <cstdint>
#include <sstream>
#include <string>

using MSHookFunctionFn=void(*)(void*,void*,void**);
using DlopenFn=void*(*)(const char*,int,const void*);
using DlopenExtFn=void*(*)(const char*,int,const void*,const void*);

static std::atomic<int> hits_dlopen{0},hits_loader{0},hits_loader_ext{0};
static DlopenFn orig_dlopen=nullptr;
static DlopenFn orig_loader=nullptr;
static DlopenExtFn orig_loader_ext=nullptr;
static bool installed=false;

static uintptr_t findSymbol(const char* lib,const char* name){
    void* h=dlopen(lib,RTLD_NOW|RTLD_NOLOAD);
    if(!h)return 0;
    void* p=dlsym(h,name);
    dlclose(h);
    return reinterpret_cast<uintptr_t>(p);
}

static void hookFn(MSHookFunctionFn hook,uintptr_t target,void* repl,void** orig){
    if(hook&&target&&!*orig)hook(reinterpret_cast<void*>(target),repl,orig);
}

static void* new_dlopen(const char* file,int flags){
    hits_dlopen++;
    return orig_dlopen?orig_dlopen(file,flags):nullptr;
}

static void* new_loader(const char* file,int flags,const void* caller){
    hits_loader++;
    return orig_loader?orig_loader(file,flags,caller):nullptr;
}

static void* new_loader_ext(const char* file,int flags,const void* ext,const void* caller){
    hits_loader_ext++;
    return orig_loader_ext?orig_loader_ext(file,flags,ext,caller):nullptr;
}

static std::string run(){
    std::ostringstream o;
    uintptr_t ms=findSymbol("libgspace_64.so","MSHookFunction");
    if(!ms)o<<"MSHookFunction=NOT_FOUND\n";
    else o<<"MSHookFunction=FOUND 0x"<<std::hex<<ms<<std::dec<<"\n";
    auto hook=reinterpret_cast<MSHookFunctionFn>(ms);
    uintptr_t d=findSymbol("libdl.so","dlopen");
    uintptr_t l=findSymbol("libgspace_64.so","__loader_dlopen");
    uintptr_t e=findSymbol("libgspace_64.so","__loader_android_dlopen_ext");
    o<<"libdl.dlopen="<<(d?"FOUND":"NOT_FOUND")<<"\n";
    o<<"__loader_dlopen="<<(l?"FOUND":"NOT_FOUND")<<"\n";
    o<<"__loader_android_dlopen_ext="<<(e?"FOUND":"NOT_FOUND")<<"\n";
    if(hook){
        hookFn(hook,d,reinterpret_cast<void*>(new_dlopen),reinterpret_cast<void**>(&orig_dlopen));
        hookFn(hook,l,reinterpret_cast<void*>(new_loader),reinterpret_cast<void**>(&orig_loader));
        hookFn(hook,e,reinterpret_cast<void*>(new_loader_ext),reinterpret_cast<void**>(&orig_loader_ext));
    }
    installed=orig_dlopen||orig_loader||orig_loader_ext;
    o<<"HOOKED dlopen="<<(orig_dlopen?"YES":"NO")<<" loader="<<(orig_loader?"YES":"NO")<<" ext="<<(orig_loader_ext?"YES":"NO")<<"\n";
    void* p=dlopen("libc.so",RTLD_NOW);
    if(p)dlclose(p);
    o<<"FORCED_DLOPEN="<<(p?"YES":"NO")<<"\n";
    o<<"HITS dlopen="<<hits_dlopen.load()<<" loader="<<hits_loader.load()<<" ext="<<hits_loader_ext.load()<<"\n";
    o<<"RESULT="<<(installed&&((hits_dlopen+hits_loader+hits_loader_ext)>0)?"REAL_HOOK_HIT":"HOOK_NO_HIT")<<"\n";
    return o.str();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst3_xposedbridgeexample_GSpaceBridge_nativeLoaderSmoke(JNIEnv* env,jclass){
    std::string s=run();
    return env->NewStringUTF(s.c_str());
}
