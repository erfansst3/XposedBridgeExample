#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <utility>
#include <algorithm>
#include <cctype>
#include <cstring>

static std::string lowerCopy(const std::string& s) {
    std::string x = s;
    std::transform(x.begin(), x.end(), x.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return x;
}

static bool relevant(const std::string& s) {
    const std::string x = lowerCopy(s);
    static const char* keys[] = {
        "sandhook", "sandvxposed", "xposed", "virtualapp",
        "com.lody.virtual", "gspace", "vxp", "sandvxp", "libva"
    };
    for (const char* k : keys) {
        if (x.find(k) != std::string::npos) return true;
    }
    return false;
}

static bool candidateSymbol(const std::string& name) {
    const std::string x = lowerCopy(name);
    static const char* keys[] = {
        "hook", "sandhook", "sandvxposed", "xposed", "virtual",
        "gspace", "artmethod", "art", "jni_onload", "stub"
    };
    for (const char* k : keys) {
        if (x.find(k) != std::string::npos) return true;
    }
    return false;
}

static std::string readText(const char* path, size_t maxBytes = 256 * 1024) {
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f) return {};
    std::string out;
    out.resize(maxBytes);
    f.read(out.data(), static_cast<std::streamsize>(maxBytes));
    out.resize(static_cast<size_t>(f.gcount()));
    return out;
}

static std::string relevantLines(const char* path, bool nulSeparated = false) {
    std::string raw = readText(path);
    if (raw.empty()) return {};
    std::ostringstream out;

    if (nulSeparated) {
        size_t start = 0;
        while (start < raw.size()) {
            size_t end = raw.find('\0', start);
            if (end == std::string::npos) end = raw.size();
            std::string item = raw.substr(start, end - start);
            if (relevant(item)) out << item << "\n";
            start = end + 1;
        }
        return out.str();
    }

    std::istringstream in(raw);
    std::string line;
    while (std::getline(in, line)) {
        if (relevant(line)) out << line << "\n";
    }
    return out.str();
}

struct ModuleInfo {
    uintptr_t base = 0;
    std::string path;
    const ElfW(Phdr)* phdr = nullptr;
    size_t phnum = 0;
};

static bool wantedModulePath(const std::string& path, const std::string& wanted) {
    const std::string p = lowerCopy(path);
    const std::string w = lowerCopy(wanted);
    const size_t slash = p.find_last_of('/');
    const std::string base = slash == std::string::npos ? p : p.substr(slash + 1);
    return base == w || p.find(w) != std::string::npos;
}

static int findModuleCallback(struct dl_phdr_info* info, size_t, void* data) {
    auto* args = static_cast<std::pair<const std::string*, ModuleInfo*>*>(data);
    if (!info->dlpi_name || !*info->dlpi_name) return 0;

    const std::string path(info->dlpi_name);
    if (!wantedModulePath(path, *args->first)) return 0;

    args->second->base = static_cast<uintptr_t>(info->dlpi_addr);
    args->second->path = path;
    args->second->phdr = info->dlpi_phdr;
    args->second->phnum = info->dlpi_phnum;
    return 1;
}

static ModuleInfo findModule(const std::string& name) {
    ModuleInfo result;
    std::pair<const std::string*, ModuleInfo*> args{&name, &result};
    dl_iterate_phdr(findModuleCallback, &args);
    return result;
}

static std::string loadedLibraries() {
    std::ostringstream out;
    struct Ctx { std::ostringstream* out; } ctx{&out};

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* ctx = static_cast<Ctx*>(data);
        const char* name = info->dlpi_name;
        if (name && *name && relevant(name)) *ctx->out << name << "\n";
        return 0;
    }, &ctx);

    return out.str();
}

static bool getDynamicInfo(
        const ModuleInfo& module,
        const ElfW(Sym)** symtabOut,
        const char** strtabOut,
        size_t* symCountOut) {

    if (!module.base || !module.phdr || !symtabOut || !strtabOut || !symCountOut)
        return false;

    const ElfW(Dyn)* dynamic = nullptr;
    for (size_t i = 0; i < module.phnum; ++i) {
        if (module.phdr[i].p_type == PT_DYNAMIC) {
            dynamic = reinterpret_cast<const ElfW(Dyn)*>(
                    module.base + module.phdr[i].p_vaddr);
            break;
        }
    }
    if (!dynamic) return false;

    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    size_t syment = sizeof(ElfW(Sym));
    const uint32_t* sysvHash = nullptr;
    const uint32_t* gnuHash = nullptr;

    for (const ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_SYMTAB:
                symtab = reinterpret_cast<const ElfW(Sym)*>(
                        module.base + d->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = reinterpret_cast<const char*>(
                        module.base + d->d_un.d_ptr);
                break;
            case DT_SYMENT:
                syment = static_cast<size_t>(d->d_un.d_val);
                break;
            case DT_HASH:
                sysvHash = reinterpret_cast<const uint32_t*>(
                        module.base + d->d_un.d_ptr);
                break;
            case DT_GNU_HASH:
                gnuHash = reinterpret_cast<const uint32_t*>(
                        module.base + d->d_un.d_ptr);
                break;
            default:
                break;
        }
    }

    if (!symtab || !strtab || syment != sizeof(ElfW(Sym))) return false;

    size_t count = 0;
    if (sysvHash) {
        count = static_cast<size_t>(sysvHash[1]);
    } else if (gnuHash) {
        const uint32_t nbuckets = gnuHash[0];
        const uint32_t symoffset = gnuHash[1];
        const uint32_t bloomSize = gnuHash[2];
        if (nbuckets == 0) {
            count = symoffset;
        } else {
            const uint32_t* buckets =
                    gnuHash + 4 +
                    static_cast<size_t>(bloomSize) * (sizeof(ElfW(Addr)) / 4);
            const uint32_t* chains = buckets + nbuckets;
            uint32_t maxIndex = symoffset;

            for (uint32_t b = 0; b < nbuckets; ++b) {
                uint32_t idx = buckets[b];
                if (idx < symoffset) continue;

                for (uint32_t walked = 0; walked < 1000000; ++walked) {
                    const uint32_t h = chains[idx - symoffset];
                    if (idx > maxIndex) maxIndex = idx;
                    if (h & 1U) break;
                    ++idx;
                }
            }
            count = static_cast<size_t>(maxIndex) + 1;
        }
    }

    if (count == 0 || count > 1000000) return false;
    *symtabOut = symtab;
    *strtabOut = strtab;
    *symCountOut = count;
    return true;
}

static uintptr_t resolveSymbolAny(const std::string& moduleName, const std::string& symbol) {
    if (moduleName.empty() || symbol.empty()) return 0;

    const ModuleInfo module = findModule(moduleName);
    if (module.path.empty()) return 0;

    void* handle = dlopen(module.path.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        void* addr = dlsym(handle, symbol.c_str());
        dlclose(handle);
        if (addr) return reinterpret_cast<uintptr_t>(addr);
    }

    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    size_t count = 0;
    if (!getDynamicInfo(module, &symtab, &strtab, &count)) return 0;

    for (size_t i = 0; i < count; ++i) {
        const ElfW(Sym)& sym = symtab[i];
        if (sym.st_name == 0) continue;
        const char* name = strtab + sym.st_name;
        if (!name || symbol != name) continue;
        if (sym.st_shndx == SHN_UNDEF || sym.st_value == 0) return 0;
        return module.base + static_cast<uintptr_t>(sym.st_value);
    }
    return 0;
}

static std::string moduleSymbols(const std::string& moduleName) {
    const ModuleInfo module = findModule(moduleName);
    std::ostringstream out;

    out << "module: " << moduleName << "\n";
    if (module.path.empty()) {
        out << "loaded: NO\n";
        return out.str();
    }

    out << "loaded: YES\n";
    out << "path: " << module.path << "\n";
    out << "base: 0x" << std::hex << module.base << std::dec << "\n";

    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    size_t count = 0;

    if (!getDynamicInfo(module, &symtab, &strtab, &count)) {
        out << "dynsym: UNAVAILABLE\n";
        return out.str();
    }

    out << "dynsym entries: " << count << "\n";

    void* handle = dlopen(module.path.c_str(), RTLD_NOW | RTLD_NOLOAD);
    size_t candidates = 0;
    size_t exports = 0;

    out << "[candidate exported functions]\n";
    for (size_t i = 0; i < count && candidates < 300; ++i) {
        const ElfW(Sym)& sym = symtab[i];
        const unsigned type = static_cast<unsigned>(sym.st_info & 0x0f);
        if (type != STT_FUNC && type != STT_GNU_IFUNC) continue;
        if (sym.st_name == 0) continue;

        const char* name = strtab + sym.st_name;
        if (!name || !*name || !candidateSymbol(name)) continue;

        void* addr = handle ? dlsym(handle, name) : nullptr;
        uintptr_t runtime = reinterpret_cast<uintptr_t>(addr);
        if (!runtime && sym.st_shndx != SHN_UNDEF && sym.st_value != 0)
            runtime = module.base + static_cast<uintptr_t>(sym.st_value);

        out << name
            << " | value=0x" << std::hex << static_cast<uintptr_t>(sym.st_value)
            << " | addr=0x" << runtime
            << std::dec << "\n";
        ++candidates;
    }
    if (candidates == 0) out << "NONE\n";

    out << "[all exported function names — first 300]\n";
    for (size_t i = 0; i < count && exports < 300; ++i) {
        const ElfW(Sym)& sym = symtab[i];
        const unsigned type = static_cast<unsigned>(sym.st_info & 0x0f);
        if (type != STT_FUNC && type != STT_GNU_IFUNC) continue;
        if (sym.st_name == 0) continue;

        const char* name = strtab + sym.st_name;
        if (!name || !*name) continue;

        out << name << "\n";
        ++exports;
    }
    if (exports == 0) out << "NONE\n";
    else if (exports >= 300) out << "(limited to 300)\n";

    if (handle) dlclose(handle);
    return out.str();
}

static std::string jniExports(const std::string& moduleName) {
    const ModuleInfo module = findModule(moduleName);
    std::ostringstream out;
    out << "module: " << moduleName << "\n";

    if (module.path.empty()) {
        out << "loaded: NO\n";
        return out.str();
    }

    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    size_t count = 0;
    if (!getDynamicInfo(module, &symtab, &strtab, &count)) {
        out << "dynsym: UNAVAILABLE\n";
        return out.str();
    }

    out << "loaded: YES\n";
    out << "base: 0x" << std::hex << module.base << std::dec << "\n";
    out << "[Java_com_* JNI exports]\n";

    size_t found = 0;
    for (size_t i = 0; i < count; ++i) {
        const ElfW(Sym)& sym = symtab[i];
        const unsigned type = static_cast<unsigned>(sym.st_info & 0x0f);
        if (type != STT_FUNC && type != STT_GNU_IFUNC) continue;
        if (sym.st_name == 0) continue;

        const char* name = strtab + sym.st_name;
        if (!name || strncmp(name, "Java_", 5) != 0) continue;

        uintptr_t runtime = 0;
        void* handle = dlopen(module.path.c_str(), RTLD_NOW | RTLD_NOLOAD);
        if (handle) {
            runtime = reinterpret_cast<uintptr_t>(dlsym(handle, name));
            dlclose(handle);
        }
        if (!runtime && sym.st_shndx != SHN_UNDEF && sym.st_value != 0)
            runtime = module.base + static_cast<uintptr_t>(sym.st_value);

        out << name
            << " | value=0x" << std::hex << static_cast<uintptr_t>(sym.st_value)
            << " | runtime=0x" << runtime
            << std::dec << "\n";
        ++found;
    }

    if (!found) out << "NONE\n";
    else out << "count: " << found << "\n";
    return out.str();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst3_xposedbridgeexample_MainActivity_nativeDiagnostics(
        JNIEnv* env, jclass) {
    std::ostringstream out;
    const std::string libs = loadedLibraries();
    const std::string maps = relevantLines("/proc/self/maps");
    const std::string mounts = relevantLines("/proc/self/mountinfo");
    const std::string environ = relevantLines("/proc/self/environ", true);

    int markerCount = 0;
    if (!libs.empty()) markerCount++;
    if (!maps.empty()) markerCount++;
    if (!mounts.empty()) markerCount++;
    if (!environ.empty()) markerCount++;

    const ModuleInfo gspace = findModule("libgspace_64.so");
    const ModuleInfo stub = findModule("libstub.so");

    out << "Native marker score: " << markerCount << "/4\n";
    out << "GSpace runtime: " << (!gspace.path.empty() ? "YES" : "NO") << "\n";
    out << "libgspace_64.so: " << (!gspace.path.empty() ? "LOADED" : "NO") << "\n";
    out << "libstub.so: " << (!stub.path.empty() ? "LOADED" : "NO") << "\n";

    if (!gspace.path.empty()) {
        out << "gspace path: " << gspace.path << "\n";
        out << "gspace base: 0x" << std::hex << gspace.base << std::dec << "\n";
    }
    if (!stub.path.empty()) {
        out << "stub path: " << stub.path << "\n";
        out << "stub base: 0x" << std::hex << stub.base << std::dec << "\n";
    }

    out << "\n[Loaded native libraries]\n";
    out << (libs.empty() ? "NONE\n" : libs);

    out << "\n[/proc/self/maps — relevant only]\n";
    out << (maps.empty() ? "NONE\n" : maps);

    out << "\n[/proc/self/mountinfo — relevant only]\n";
    out << (mounts.empty() ? "NONE\n" : mounts);

    out << "\n[Environment — relevant only]\n";
    out << (environ.empty() ? "NONE\n" : environ);

    out << "\n[libstub.so API]\n";
    out << moduleSymbols("libstub.so");
    out << "\n[libstub.so JNI EXPORTS]\n";
    out << jniExports("libstub.so");

    out << "\n[libgspace_64.so API]\n";
    out << moduleSymbols("libgspace_64.so");
    out << "\n[libgspace_64.so JNI EXPORTS]\n";
    out << jniExports("libgspace_64.so");

    return env->NewStringUTF(out.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst3_xposedbridgeexample_GSpaceBridge_nativeReport(
        JNIEnv* env, jclass) {
    const std::string result =
            moduleSymbols("libstub.so") +
            "\n" +
            moduleSymbols("libgspace_64.so");
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_erfansst3_xposedbridgeexample_GSpaceBridge_nativeResolve(
        JNIEnv* env, jclass, jstring libraryName, jstring symbolName) {
    if (!libraryName || !symbolName) return 0;

    const char* lib = env->GetStringUTFChars(libraryName, nullptr);
    const char* sym = env->GetStringUTFChars(symbolName, nullptr);
    if (!lib || !sym) {
        if (lib) env->ReleaseStringUTFChars(libraryName, lib);
        if (sym) env->ReleaseStringUTFChars(symbolName, sym);
        return 0;
    }

    const uintptr_t address = resolveSymbolAny(lib, sym);

    env->ReleaseStringUTFChars(libraryName, lib);
    env->ReleaseStringUTFChars(symbolName, sym);
    return static_cast<jlong>(address);
}

using SandHookCanGetObjectFn = jboolean (*)(JNIEnv*, jclass);
using SandHookHookMethodFn = jint (*)(JNIEnv*, jclass, jobject, jobject, jobject, jint);
using SandHookInitNativeFn = jboolean (*)(JNIEnv*, jclass, jint, jboolean);

extern "C" JNIEXPORT jboolean JNICALL
Java_com_erfansst3_xposedbridgeexample_GSpaceBridge_nativeInitSandHook(
        JNIEnv* env, jclass, jint sdkInt, jboolean debug) {
    const uintptr_t addr = resolveSymbolAny(
            "libgspace_64.so",
            "Java_com_swift_sandhook_SandHook_initNative");
    if (!addr) return JNI_FALSE;

    auto fn = reinterpret_cast<SandHookInitNativeFn>(addr);
    return fn(env, nullptr, sdkInt, debug);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_erfansst3_xposedbridgeexample_GSpaceBridge_nativeCanGetObject(
        JNIEnv* env, jclass) {
    const uintptr_t addr = resolveSymbolAny(
            "libgspace_64.so",
            "Java_com_swift_sandhook_SandHook_canGetObject");
    if (!addr) return JNI_FALSE;

    auto fn = reinterpret_cast<SandHookCanGetObjectFn>(addr);
    return fn(env, nullptr);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_erfansst3_xposedbridgeexample_GSpaceBridge_nativeHookMethod(
        JNIEnv* env, jclass, jobject origin, jobject hook, jobject backup, jint mode) {
    if (!origin || !hook) return -2;

    const uintptr_t addr = resolveSymbolAny(
            "libgspace_64.so",
            "Java_com_swift_sandhook_SandHook_hookMethod");
    if (!addr) return -3;

    auto fn = reinterpret_cast<SandHookHookMethodFn>(addr);
    return fn(env, nullptr, origin, hook, backup, mode);
}

jint JNI_OnLoad(JavaVM*, void*) {
    return JNI_VERSION_1_6;
}
