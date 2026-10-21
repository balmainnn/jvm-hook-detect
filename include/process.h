#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace jhd {
struct ProcessInfo {
    DWORD pid{};
    std::wstring image_name;
    std::wstring executable_path;
};

struct ModuleInfo {
    std::uintptr_t base{};
    std::size_t size{};
    std::wstring name;
    std::wstring path;
};

class Process final {
public:
    Process() = default;
    ~Process();
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&& other) noexcept;
    Process& operator=(Process&& other) noexcept;

    bool open(DWORD pid, std::wstring& error);
    void close() noexcept;
    [[nodiscard]] HANDLE handle() const noexcept { return handle_; }
    [[nodiscard]] DWORD pid() const noexcept { return pid_; }
    [[nodiscard]] bool is_open() const noexcept { return handle_ != nullptr; }

private:
    HANDLE handle_{};
    DWORD pid_{};
};

std::vector<ProcessInfo> enumerate_java_processes();
std::vector<ModuleInfo> enumerate_modules(const Process& process, std::wstring& error);
bool read_memory(const Process& process, std::uintptr_t address, void* buffer,
                 std::size_t size, std::size_t& bytes_read) noexcept;
bool is_address_in_module(std::uintptr_t address, const std::vector<ModuleInfo>& modules);
std::wstring lower_copy(std::wstring value);
}
