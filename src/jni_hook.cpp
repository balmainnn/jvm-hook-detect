#include "jni_hook.h"
#include <windows.h>
#include <algorithm>

namespace jhd {
void inspect_jvm_exports(const Process& process,
                         const std::vector<ModuleInfo>& modules,
                         std::vector<Finding>& findings) {
    const auto it = std::find_if(modules.begin(), modules.end(), [](const ModuleInfo& m) {
        const auto name = lower_copy(m.name);
        return name == L"jvm.dll";
    });
    if (it == modules.end()) {
        findings.push_back({Severity::Info, "jvm-export-check",
            "jvm.dll was not found in the enumerated module list; export integrity check skipped.",
            0, 0});
        return;
    }

    // Resolve the known export address locally only to obtain the documented export RVA.
    // Compare that RVA with the target's expected address. This does not read or execute
    // arbitrary target code and does not attempt to discover opaque JNI table instances.
    HMODULE localJvm = LoadLibraryExW(L"jvm.dll", nullptr,
        DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!localJvm) {
        findings.push_back({Severity::Info, "jvm-export-check",
            "Could not resolve a local jvm.dll export for comparison; check skipped.", it->base, 0});
        return;
    }
    FARPROC localExport = GetProcAddress(localJvm, "JNI_GetCreatedJavaVMs");
    if (!localExport) {
        FreeLibrary(localJvm);
        findings.push_back({Severity::Info, "jvm-export-check",
            "JNI_GetCreatedJavaVMs export was not available in the local JVM library; check skipped.",
            it->base, 0});
        return;
    }

    const auto rva = reinterpret_cast<std::uintptr_t>(localExport) -
                     reinterpret_cast<std::uintptr_t>(localJvm);
    const auto expected = it->base + rva;
    std::uint8_t bytes[16]{};
    std::size_t bytesRead = 0;
    const bool readable = read_memory(process, expected, bytes, sizeof(bytes), bytesRead);
    FreeLibrary(localJvm);

    if (!readable) {
        findings.push_back({Severity::Warning, "jvm-export-unreadable",
            "Could not read bytes at the expected JNI_GetCreatedJavaVMs address; access or module-version differences may explain this.",
            expected, bytesRead});
        return;
    }

    // This is intentionally conservative: reading the bytes does not establish that the
    // export is hooked. Strong conclusions require architecture-aware disassembly and a
    // matching build identity; this utility does not label byte patterns as proof.
    findings.push_back({Severity::Info, "jvm-export-sampled",
        "Read 16 bytes at the expected JNI_GetCreatedJavaVMs export address. Raw bytes are not classified as a hook without build-aware disassembly.",
        expected, sizeof(bytes)});
}
}
