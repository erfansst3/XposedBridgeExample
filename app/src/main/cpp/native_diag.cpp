#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
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
        "gspace", "artmethod", "art", "jni_onload"
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

struct GspaceModule {
    uintptr_t base = 0;
    std::string path;
    const ElfW(Phdr)* phdr = nullptr;
    size_t phnum = 0;
};

static int findGspaceCallback(struct dl_phdr_info* info, size_t, void* data) {
    auto* out = static_cast<GspaceModule*>(data);
    const char* name = info->dlpi_name;
    if (!name || !*name) return 0;
    std::string path(name);
    std::string lower = lowerCopy(path);
    if (lower.find("libgspace_64.so") != std::string::npos) {
        out->base = static_cast<uintptr_t>(info->dlpi_addr);
        out->path = path;
        out->phdr = info->dlpi_phdr;
        out->phnum = info->dlpi_phnum;
        return 1;
    }
    return 0;
}

static GspaceModule findGspaceModule() {
    GspaceModule module;
    dl_iterate_phdr(findGspaceCallback, &module);
    return module;
}

static std::string loadedLibraries() {
    std::ostringstream out;
    struct Ctx { std::ostringstream* out; } ctx{&out};

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto* ctx = static_cast<Ctx*>(data);
        const char* name = info->dlpi_name;
        if (name && *name && relevant(name)) {
            *ctx->out << name << "\n";
        }
        return 0;
    }, &ctx);

    return out.str();
}

static bool getDynamicInfo(
        const GspaceModule& module,
        const ElfW(Sym)** symtabOut,
        const char** strtabOut,
        size_t* symCountOut) {

    if (!module.base || !module.phdr || !symtabOut || !strtabOut || !symCountOut)
        return false;

    const ElfW(Dyn)* dynamic = nullptr;
    for (size_t i = 0; i < module.phnum; ++i) {
        const ElfW(Phdr)& ph = module.phdr[i];
        if (ph.p_type == PT_DYNAMIC) {
            dynamic = reinterpret_cast<const ElfW(Dyn)*>(module.base + ph.p_vaddr);
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
                symtab = reinterpret_cast<const ElfW(Sym)*>(module.base + d->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = reinterpret_cast<const char*>(module.base + d->d_un.d_ptr);
                break;
            case DT_SYMENT:
                syment = static_cast<size_t>(d->d_un.d_val);
                break;
            case DT_HASH:
                sysvHash = reinterpret_cast<const uint32_t*>(module.base + d->d_un.d_ptr);
                break;
            case DT_GNU_HASH:
                gnuHash = reinterpret_cast<const uint32_t*>(module.base + d->d_un.d_ptr);
                break;
            default:
                break;
        }
    }

    if (!symtab || !strtab || syment != sizeof(ElfW(Sym))) return false;

    size_t count = 0;
    if (sysvHash) {
        // SysV hash: [nbucket, nchain, buckets..., chains...]
        count = static_cast<size_t>(sysvHash[1]);
    } else if (gnuHash) {
        // GNU hash: derive the highest dynsym index from the bucket/chain data.
        const uint32_t nbuckets = gnuHash[0];
        const uint32_t symoffset = gnuHash[1];
        const uint32_t bloomSize = gnuHash[2];
        if (nbuckets == 0) {
            count = symoffset;
        } else {
            const uint32_t* buckets = gnuHash + 4 + (static_cast<size_t>(bloomSize) * (sizeof(ElfW(Addr)) / 4));
            const uint32_t* chains = buckets + nbuckets;
            uint32_t maxIndex = symoffset;
            const uint32_t hardLimit = 1000000;
            for (uint32_t b = 0; b < nbuckets; ++b) {
                uint32_t idx = buckets[b];
                if (idx < symoffset) continue;
                uint32_t walked = 0;
                while (walked++ < hardLimit) {
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

static std::string gspaceCandidates() {
    const GspaceModule module = findGspaceModule();
    if (module.path.empty()) return "GSpace library not loaded\n";

    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    size_t count = 0;
    if (!getDynamicInfo(module, &symtab, &strtab, &count))
        return "GSpace dynsym unavailable\n";

    void* handle = dlopen(module.path.c_str(), RTLD_NOW | RTLD_NOLOAD);
    std::ostringstream out;
    size_t shown = 0;

    out << "library: " << module.path << "\n";
    out << "base: 0x" << std::hex << module.base << std::dec << "\n";
    out << "dynsym entries: " << count << "\n";

    for (size_t i = 0; i < count && shown < 200; ++i) {
        const ElfW(Sym)& sym = symtab[i];
        const unsigned type = ELF64_ST_TYPE(sym.st_info);
        if (type != STT_FUNC && type != STT_GNU_IFUNC) continue;
        if (sym.st_name == 0) continue;

        const char* name = strtab + sym.st_name;
        if (!name || !*name) continue;
        if (!candidateSymbol(name)) continue;

        void* addr = nullptr;
        if (handle) addr = dlsym(handle, name);

        out << name
            << " | value=0x" << std::hex << static_cast<uintptr_t>(sym.st_value)
            << " | addr=0x" << reinterpret_cast<uintptr_t>(addr)
            << std::dec << "\n";
        ++shown;
    }

    if (handle) dlclose(handle);
    if (shown == 0) out << "No matching exported function symbols\n";
    else if (shown >= 200) out << "(limited to 200 candidates)\n";

    return out.str();
}

static uintptr_t resolveGspaceSymbol(const std::string& symbol) {
    const GspaceModule module = findGspaceModule();
    if (module.path.empty() || symbol.empty()) return 0;

    void* handle = dlopen(module.path.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (!handle) return 0;

    void* addr = dlsym(handle, symbol.c_str());
    dlclose(handle);
    return reinterpret_cast<uintptr_t>(addr);
}

static pid_t parentPid() {
    std::string stat = readText("/proc/self/stat", 4096);
    if (stat.empty()) return -1;
    size_t close = stat.rfind(')');
    if (close == std::string::npos || close + 2 >= stat.size()) return -1;

    std::istringstream in(stat.substr(close + 2));
    char state = 0;
    long ppid = -1;
    in >> state >> ppid;
    return static_cast<pid_t>(ppid);
}

static std::string cmdlineFor(pid_t pid) {
    if (pid <= 0) return {};
    std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::string raw = readText(path.c_str(), 4096);
    for (char& c : raw) if (c == '\0') c = ' ';
    return raw;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst3_xposedbridgeexample_MainActivity_nativeDiagnostics(
        JNIEnv* env, jclass) {

    std::ostringstream out;
    int markerCount = 0;

    std::string libs = loadedLibraries();
    if (!libs.empty()) markerCount++;

    std::string maps = relevantLines("/proc/self/maps");
    if (!maps.empty()) markerCount++;

    std::string mounts = relevantLines("/proc/self/mountinfo");
    if (!mounts.empty()) markerCount++;

    std::string environ = relevantLines("/proc/self/environ", true);
    if (!environ.empty()) markerCount++;

    const GspaceModule gspace = findGspaceModule();
    const bool gspaceReady = !gspace.path.empty();

    std::string selfCmd = cmdlineFor(getpid());
    std::string parentCmd = cmdlineFor(parentPid());
    std::string parentHit = relevant(parentCmd) ? parentCmd : "";

    out << "Native marker score: " << markerCount << "/4\n";
    out << "GSpace native runtime: " << (gspaceReady ? "YES" : "NO") << "\n";
    if (gspaceReady) {
        out << "GSpace library: " << gspace.path << "\n";
        out << "GSpace load base: 0x" << std::hex << gspace.base << std::dec << "\n";
    }

    out << "\n[Loaded native libraries]\n";
    out << (libs.empty() ? "NONE\n" : libs);

    out << "\n[/proc/self/maps — relevant only]\n";
    out << (maps.empty() ? "NONE\n" : maps);

    out << "\n[/proc/self/mountinfo — relevant only]\n";
    out << (mounts.empty() ? "NONE\n" : mounts);

    out << "\n[Environment — relevant only]\n";
    out << (environ.empty() ? "NONE\n" : environ);

    out << "\n[Process]\n";
    out << "self cmdline: " << (selfCmd.empty() ? "-" : selfCmd) << "\n";
    out << "parent pid: " << parentPid() << "\n";
    out << "relevant parent cmdline: " << (parentHit.empty() ? "NONE" : parentHit) << "\n";

    out << "\n=== GSPACE NATIVE API BRIDGE ===\n";
    out << gspaceCandidates();

    return env->NewStringUTF(out.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst3_xposedbridgeexample_GSpaceBridge_nativeReport(
        JNIEnv* env, jclass) {
    return env->NewStringUTF(gspaceCandidates().c_str());
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_erfansst3_xposedbridgeexample_GSpaceBridge_nativeResolve(
        JNIEnv* env, jclass, jstring symbolName) {
    if (!symbolName) return 0;
    const char* chars = env->GetStringUTFChars(symbolName, nullptr);
    if (!chars) return 0;
    uintptr_t address = resolveGspaceSymbol(chars);
    env->ReleaseStringUTFChars(symbolName, chars);
    return static_cast<jlong>(address);
}

jint JNI_OnLoad(JavaVM*, void*) {
    return JNI_VERSION_1_6;
}
