#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <iomanip>

struct ModuleInfo {
    uintptr_t base = 0;
    std::string path;
    const ElfW(Phdr)* phdr = nullptr;
    size_t phnum = 0;
};

static int findModuleCallback(struct dl_phdr_info* info, size_t, void* data) {
    auto* out = static_cast<ModuleInfo*>(data);
    if (!info->dlpi_name || !*info->dlpi_name) return 0;
    std::string path(info->dlpi_name);
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower.find("libgspace_64.so") == std::string::npos) return 0;
    out->base = static_cast<uintptr_t>(info->dlpi_addr);
    out->path = path;
    out->phdr = info->dlpi_phdr;
    out->phnum = info->dlpi_phnum;
    return 1;
}

static ModuleInfo findGSpace() {
    ModuleInfo m;
    dl_iterate_phdr(findModuleCallback, &m);
    return m;
}

static void scanWritableForPointer(
        const ModuleInfo& m,
        uintptr_t target,
        std::vector<uintptr_t>& matches,
        size_t maxMatches = 32) {
    if (!m.base || !m.phdr || !target) return;

    for (size_t i = 0; i < m.phnum && matches.size() < maxMatches; ++i) {
        const ElfW(Phdr)& ph = m.phdr[i];
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_W) || ph.p_memsz == 0) continue;

        uintptr_t start = m.base + static_cast<uintptr_t>(ph.p_vaddr);
        size_t len = static_cast<size_t>(ph.p_memsz);

        // Avoid pathological scans while still covering normal .data/.bss.
        const size_t kMaxSegment = 64u * 1024u * 1024u;
        if (len > kMaxSegment) len = kMaxSegment;

        const size_t step = sizeof(uintptr_t);
        for (size_t off = 0; off + step <= len && matches.size() < maxMatches; off += step) {
            uintptr_t value = *reinterpret_cast<const uintptr_t*>(start + off);
            if (value == target) matches.push_back(start + off);
        }
    }
}

static std::string directDlsym(void* handle, const char* symbol) {
    void* p = handle ? dlsym(handle, symbol) : nullptr;
    std::ostringstream out;
    out << "0x" << std::hex << reinterpret_cast<uintptr_t>(p);
    return out.str();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst3_xposedbridgeexample_GSpaceBridge_nativeDeepInspectSandHook(
        JNIEnv* env, jclass) {
    static const char* kWeakOld =
            "_ZN3art9JavaVMExt16AddWeakGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE";
    static const char* kWeakQ =
            "_ZN3art9JavaVMExt16AddWeakGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE";

    const ModuleInfo gspace = findGSpace();
    std::ostringstream out;
    out << "=== SANDHOOK DEEP READ-ONLY INSPECTOR ===\n";
    out << "Pointer size: " << sizeof(void*) * 8 << "-bit\n";
    out << "GSpace loaded: " << (!gspace.path.empty() ? "YES" : "NO") << "\n";
    if (!gspace.path.empty()) {
        out << "GSpace path: " << gspace.path << "\n";
        out << "GSpace base: 0x" << std::hex << gspace.base << std::dec << "\n";
    }

    void* artHandle = nullptr;
    uintptr_t artWeakOld = 0;
    uintptr_t artWeakQ = 0;
    if (gspace.path.empty()) {
        out << "No GSpace module; stopping.\n";
        return env->NewStringUTF(out.str().c_str());
    }

    // Prefer the already loaded ART image. RTLD_NOLOAD is read-only.
    artHandle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
    if (!artHandle) artHandle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);

    artWeakOld = reinterpret_cast<uintptr_t>(
            dlsym(artHandle, kWeakOld));
    artWeakQ = reinterpret_cast<uintptr_t>(
            dlsym(artHandle, kWeakQ));

    out << "\n[ART dlsym check]\n";
    out << "libart handle: 0x" << std::hex
        << reinterpret_cast<uintptr_t>(artHandle) << std::dec << "\n";
    out << "dlsym(RTLD_DEFAULT, AddWeakGlobalRef(old)): 0x" << std::hex
        << reinterpret_cast<uintptr_t>(dlsym(RTLD_DEFAULT, kWeakOld)) << std::dec << "\n";
    out << "dlsym(RTLD_DEFAULT, AddWeakGlobalRef(Q+)): 0x" << std::hex
        << reinterpret_cast<uintptr_t>(dlsym(RTLD_DEFAULT, kWeakQ)) << std::dec << "\n";
    out << "dlsym(libart, AddWeakGlobalRef(old)): 0x" << std::hex
        << artWeakOld << std::dec << "\n";
    out << "dlsym(libart, AddWeakGlobalRef(Q+)): 0x" << std::hex
        << artWeakQ << std::dec << "\n";

    if (artHandle) {
        dlclose(artHandle);
        artHandle = nullptr;
    }

    const uintptr_t initNative = reinterpret_cast<uintptr_t>(
            dlsym(RTLD_DEFAULT, "Java_com_swift_sandhook_SandHook_initNative"));
    const uintptr_t canGet = reinterpret_cast<uintptr_t>(
            dlsym(RTLD_DEFAULT, "Java_com_swift_sandhook_SandHook_canGetObject"));
    const uintptr_t hookMethod = reinterpret_cast<uintptr_t>(
            dlsym(RTLD_DEFAULT, "Java_com_swift_sandhook_SandHook_hookMethod"));

    out << "\n[SandHook JNI lookup through RTLD_DEFAULT]\n";
    out << "initNative: 0x" << std::hex << initNative << std::dec << "\n";
    out << "canGetObject: 0x" << std::hex << canGet << std::dec << "\n";
    out << "hookMethod: 0x" << std::hex << hookMethod << std::dec << "\n";

    // We do not call any SandHook method here. Only locate the exported functions.
    if (gspace.base && canGet >= gspace.base) {
        out << "canGetObject offset from GSpace: 0x" << std::hex
            << (canGet - gspace.base) << std::dec << "\n";
    }

    out << "\n[Writable-data pointer scan]\n";
    if (artWeakQ) {
        std::vector<uintptr_t> qMatches;
        scanWritableForPointer(gspace, artWeakQ, qMatches);
        out << "Matches for ART AddWeakGlobalRef(Q+) = " << qMatches.size() << "\n";
        for (uintptr_t p : qMatches) {
            out << "  slot=0x" << std::hex << p << std::dec
                << " -> 0x" << std::hex << artWeakQ << std::dec << "\n";
        }
        if (qMatches.empty()) {
            out << "No writable GSpace word currently equals the ART Q+ function address.\n";
        }
    } else {
        out << "Cannot scan: ART Q+ address unavailable via dlsym.\n";
    }

    if (artWeakOld) {
        std::vector<uintptr_t> oldMatches;
        scanWritableForPointer(gspace, artWeakOld, oldMatches);
        out << "Matches for ART AddWeakGlobalRef(old) = " << oldMatches.size() << "\n";
        for (uintptr_t p : oldMatches) {
            out << "  slot=0x" << std::hex << p << std::dec
                << " -> 0x" << std::hex << artWeakOld << std::dec << "\n";
        }
    }

    out << "\n[Safety]\n";
    out << "This inspector performs no writes, no hook installation, and no SandHook initialization.\n";

    return env->NewStringUTF(out.str().c_str());
}
