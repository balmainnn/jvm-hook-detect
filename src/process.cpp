#include "process.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <cwctype>
#include <vector>

namespace jhd {
Process::~Process() { close(); }

Process::Process(Process&& other) noexcept : handle_(other.handle_), pid_(other.pid_) {
    other.handle_ = nullptr;
    other.pid_ = 0;
}

Process& Process::operator=(Process&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        pid_ = other.pid_;
        other.handle_ = nullptr;
        other.pid_ = 0;
    }
    return *this;
}

bool Process::open(DWORD pid, std::wstring& error) {
    close();
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        error = L"OpenProcess failed (error " + std::to_wstring(GetLastError()) + L")";
        return false;
    }
    handle_ = h;
    pid_ = pid;
    return true;
}

void Process::close() noexcept {
    if (handle_) CloseHandle(handle_);
    handle_ = nullptr;
    pid_ = 0;
}

std::wstring lower_copy(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}

std::vector<ProcessInfo> enumerate_java_processes() {
    std::vector<ProcessInfo> result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            const std::wstring image = entry.szExeFile;
            const std::wstring lower = lower_copy(image);
            if (lower != L"java.exe" && lower != L"javaw.exe") continue;

            ProcessInfo info{};
            info.pid = entry.th32ProcessID;
            info.image_name = image;
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid);
            if (process) {
                std::vector<wchar_t> path(32768);
                DWORD length = static_cast<DWORD>(path.size());
                if (QueryFullProcessImageNameW(process, 0, path.data(), &length))
                    info.executable_path.assign(path.data(), length);
                CloseHandle(process);
            }
            result.push_back(std::move(info));
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

std::vector<ModuleInfo> enumerate_modules(const Process& process, std::wstring& error) {
    std::vector<ModuleInfo> result;
    if (!process.is_open()) {
        error = L"Process is not open";
        return result;
    }

    std::vector<HMODULE> handles(512);
    DWORD needed = 0;
    if (!EnumProcessModulesEx(process.handle(), handles.data(),
            static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL)) {
        error = L"EnumProcessModulesEx failed (error " + std::to_wstring(GetLastError()) + L")";
        return result;
    }
    while (needed > handles.size() * sizeof(HMODULE)) {
        handles.resize(needed / sizeof(HMODULE) + 32);
        if (!EnumProcessModulesEx(process.handle(), handles.data(),
                static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL)) {
            error = L"EnumProcessModulesEx retry failed (error " + std::to_wstring(GetLastError()) + L")";
            return {};
        }
    }

    const std::size_t count = std::min<std::size_t>(handles.size(), needed / sizeof(HMODULE));
    for (std::size_t i = 0; i < count; ++i) {
        MODULEINFO mi{};
        if (!GetModuleInformation(process.handle(), handles[i], &mi, sizeof(mi))) continue;
        std::vector<wchar_t> name(2048), path(32768);
        DWORD name_len = GetModuleBaseNameW(process.handle(), handles[i], name.data(),
                                            static_cast<DWORD>(name.size()));
        DWORD path_len = GetModuleFileNameExW(process.handle(), handles[i], path.data(),
                                              static_cast<DWORD>(path.size()));
        ModuleInfo m{};
        m.base = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
        m.size = static_cast<std::size_t>(mi.SizeOfImage);
        if (name_len) m.name.assign(name.data(), name_len);
        if (path_len) m.path.assign(path.data(), path_len);
        result.push_back(std::move(m));
    }
    return result;
}

bool read_memory(const Process& process, std::uintptr_t address, void* buffer,
                 std::size_t size, std::size_t& bytes_read) noexcept {
    bytes_read = 0;
    if (!process.is_open() || !buffer || size == 0) return false;
    SIZE_T read = 0;
    const BOOL ok = ReadProcessMemory(process.handle(),
        reinterpret_cast<LPCVOID>(address), buffer, size, &read);
    bytes_read = static_cast<std::size_t>(read);
    return ok != FALSE && read == size;
}

bool is_address_in_module(std::uintptr_t address, const std::vector<ModuleInfo>& modules) {
    for (const auto& module : modules) {
        if (address >= module.base && address - module.base < module.size) return true;
    }
    return false;
}
}
