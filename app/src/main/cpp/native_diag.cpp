#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>

static bool relevant(const std::string& s) {
    std::string x = s;
    std::transform(x.begin(), x.end(), x.begin(), ::tolower);
    static const char* keys[] = {
        "sandhook",
        "sandvxposed",
        "xposed",
        "virtualapp",
        "com.lody.virtual",
        "gspace",
        "vxp",
        "sandvxp",
        "libva"
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

    std::string selfCmd = cmdlineFor(getpid());
    std::string parentCmd = cmdlineFor(parentPid());
    std::string parentHit = relevant(parentCmd) ? parentCmd : "";

    out << "Native marker score: " << markerCount << "/4\n";

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

    return env->NewStringUTF(out.str().c_str());
}

jint JNI_OnLoad(JavaVM* vm, void*) {
    return JNI_VERSION_1_6;
}
