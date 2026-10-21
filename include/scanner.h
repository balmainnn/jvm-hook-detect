#pragma once
#include "process.h"
#include <string>
#include <vector>
#include <cstdint>

namespace jhd {
enum class Severity { Info, Warning, Critical };

struct Finding {
    Severity severity{Severity::Info};
    std::string category;
    std::string message;
    std::uintptr_t address{};
    std::size_t size{};
};

struct ScanResult {
    DWORD pid{};
    std::wstring process_name;
    std::vector<ModuleInfo> modules;
    std::vector<Finding> findings;
    bool memory_scan_complete{true};
    std::string note;
};

ScanResult scan_process(const ProcessInfo& target);
const char* severity_name(Severity severity) noexcept;
std::string narrow_ascii(const std::wstring& value);
}
