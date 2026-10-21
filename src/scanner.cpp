#include "scanner.h"
#include "jni_hook.h"
#include <windows.h>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace jhd {
namespace {
bool is_executable_protection(DWORD protection) {
    if (protection & PAGE_GUARD) return false;
    const DWORD p = protection & 0xff;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}
bool is_writable_executable(DWORD protection) {
    const DWORD p = protection & 0xff;
    return (p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY) &&
           !(protection & PAGE_GUARD);
}
std::string hex_address(std::uintptr_t address) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << address;
    return out.str();
}
}

const char* severity_name(Severity severity) noexcept {
    switch (severity) {
    case Severity::Info: return "INFO";
    case Severity::Warning: return "WARNING";
    case Severity::Critical: return "CRITICAL";
    }
    return "INFO";
}

std::string narrow_ascii(const std::wstring& value) {
    std::string out;
    out.reserve(value.size());
    for (wchar_t c : value) out.push_back(c >= 32 && c <= 126 ? static_cast<char>(c) : '?');
    return out;
}

ScanResult scan_process(const ProcessInfo& target) {
    ScanResult result{};
    result.pid = target.pid;
    result.process_name = target.image_name;

    Process process;
    std::wstring error;
    if (!process.open(target.pid, error)) {
        result.memory_scan_complete = false;
        result.note = "Could not open process; try an elevated terminal if authorized.";
        result.findings.push_back({Severity::Warning, "process-open",
            narrow_ascii(error), 0, 0});
        return result;
    }

    result.modules = enumerate_modules(process, error);
    if (!error.empty()) {
        result.memory_scan_complete = false;
        result.findings.push_back({Severity::Warning, "module-enumeration",
            narrow_ascii(error), 0, 0});
    }

    std::uintptr_t cursor = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    constexpr std::uintptr_t max_address = static_cast<std::uintptr_t>(0x00007FFFFFFFFFFFULL);
    std::size_t regions_seen = 0;
    while (cursor < max_address && regions_seen < 2'000'000) {
        if (VirtualQueryEx(process.handle(), reinterpret_cast<LPCVOID>(cursor),
                           &mbi, sizeof(mbi)) == 0) {
            const DWORD e = GetLastError();
            if (e == ERROR_INVALID_PARAMETER) break;
            const std::uintptr_t next = cursor + 0x10000;
            if (next <= cursor) break;
            cursor = next;
            result.memory_scan_complete = false;
            continue;
        }
        ++regions_seen;
        const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const auto size = static_cast<std::size_t>(mbi.RegionSize);
        if (size == 0 || base > max_address - std::min<std::uintptr_t>(size, max_address)) break;

        if (mbi.State == MEM_COMMIT && is_executable_protection(mbi.Protect)) {
            const bool backed_by_enumerated_module = is_address_in_module(base, result.modules);
            if (!backed_by_enumerated_module) {
                const bool rwx = is_writable_executable(mbi.Protect);
                result.findings.push_back({
                    rwx ? Severity::Critical : Severity::Warning,
                    rwx ? "unbacked-rwx-region" : "unbacked-executable-region",
                    std::string(rwx ? "Committed RWX/RWX-copy executable region not covered by an enumerated module at "
                                    : "Executable region not covered by an enumerated module at ") +
                        hex_address(base) + ". Heuristic only; JIT runtimes can legitimately allocate executable memory.",
                    base, size
                });
            }
        }
        const std::uintptr_t next = base + size;
        if (next <= cursor) break;
        cursor = next;
    }

    if (regions_seen >= 2'000'000) {
        result.memory_scan_complete = false;
        result.findings.push_back({Severity::Warning, "scan-limit",
            "Memory scan stopped at the safety limit of 2,000,000 regions.", 0, 0});
    }

    inspect_jvm_exports(process, result.modules, result.findings);
    if (result.findings.empty()) {
        result.findings.push_back({Severity::Info, "no-findings",
            "No heuristic findings were reported. This is not proof that the process is clean.", 0, 0});
    }
    return result;
}
}
