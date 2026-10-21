#include "process.h"
#include "scanner.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>

namespace {
struct Options { bool json{false}; DWORD pid{0}; bool list{false}; };

void usage() {
    std::cout << "jvm-hook-detect - read-only JVM process heuristic scanner\n"
              << "Usage:\n"
              << "  jvm-hook-detect.exe [--list] [--pid <PID>] [--json [report.json]]\n\n"
              << "Options:\n"
              << "  --list          List java.exe/javaw.exe processes\n"
              << "  --pid <PID>     Scan a specific Java process\n"
              << "  --json [FILE]   Write JSON report to FILE (default: stdout)\n"
              << "  --help          Show this help\n";
}
std::string json_escape(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            else out << c;
        }
    }
    return out.str();
}
std::string json_report(const jhd::ScanResult& r) {
    std::ostringstream out;
    out << "{\n  \"pid\": " << r.pid
        << ",\n  \"process\": \"" << json_escape(jhd::narrow_ascii(r.process_name)) << "\""
        << ",\n  \"memory_scan_complete\": " << (r.memory_scan_complete ? "true" : "false")
        << ",\n  \"note\": \"" << json_escape(r.note) << "\""
        << ",\n  \"modules\": [";
    for (std::size_t i = 0; i < r.modules.size(); ++i) {
        const auto& m = r.modules[i];
        out << (i ? "," : "") << "\n    {\"name\":\"" << json_escape(jhd::narrow_ascii(m.name))
            << "\",\"path\":\"" << json_escape(jhd::narrow_ascii(m.path))
            << "\",\"base\":" << m.base << ",\"size\":" << m.size << "}";
    }
    if (!r.modules.empty()) out << "\n  ";
    out << "],\n  \"findings\": [";
    for (std::size_t i = 0; i < r.findings.size(); ++i) {
        const auto& f = r.findings[i];
        out << (i ? "," : "") << "\n    {\"severity\":\"" << jhd::severity_name(f.severity)
            << "\",\"category\":\"" << json_escape(f.category)
            << "\",\"message\":\"" << json_escape(f.message)
            << "\",\"address\":" << f.address << ",\"size\":" << f.size << "}";
    }
    if (!r.findings.empty()) out << "\n  ";
    out << "]\n}\n";
    return out.str();
}
Options parse(int argc, wchar_t** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--help" || arg == L"-h") { usage(); std::exit(0); }
        if (arg == L"--list") o.list = true;
        else if (arg == L"--pid" && i + 1 < argc) {
            try { o.pid = static_cast<DWORD>(std::stoul(argv[++i])); } catch (...) {
                std::cerr << "Invalid PID.\n"; std::exit(2);
            }
        } else if (arg == L"--json") {
            o.json = true;
        } else {
            std::wcerr << L"Unknown or incomplete option: " << arg << L"\n";
            std::exit(2);
        }
    }
    return o;
}
void print_finding(const jhd::Finding& f) {
    const char* color = f.severity == jhd::Severity::Critical ? "\x1b[31m" :
                        f.severity == jhd::Severity::Warning ? "\x1b[33m" : "\x1b[36m";
    std::cout << color << "[" << jhd::severity_name(f.severity) << "]\x1b[0m "
              << f.category << ": " << f.message;
    if (f.address) std::cout << " (address=0x" << std::hex << f.address << std::dec
                             << ", size=" << f.size << ")";
    std::cout << "\n";
}
}

int wmain(int argc, wchar_t** argv) {
    const Options options = parse(argc, argv);
    const auto processes = jhd::enumerate_java_processes();
    if (options.list || options.pid == 0) {
        if (processes.empty()) std::cout << "No java.exe/javaw.exe processes found.\n";
        for (const auto& p : processes) {
            std::wcout << L"PID " << p.pid << L"  " << p.image_name;
            if (!p.executable_path.empty()) std::wcout << L"  " << p.executable_path;
            std::wcout << L"\n";
        }
        if (options.pid == 0) {
            if (!options.json) usage();
            return processes.empty() ? 1 : 0;
        }
    }

    jhd::ProcessInfo target{};
    bool found = false;
    for (const auto& p : processes) if (p.pid == options.pid) { target = p; found = true; break; }
    if (!found) {
        std::cerr << "PID was not found among java.exe/javaw.exe processes. Use --list to inspect targets.\n";
        return 2;
    }

    const auto result = jhd::scan_process(target);
    if (options.json) {
        const std::string report = json_report(result);
        std::cout << report;
    } else {
        std::wcout << L"Scanning " << target.image_name << L" (PID " << target.pid << L")\n";
        std::cout << "Enumerated modules: " << result.modules.size()
                  << ", scan complete: " << (result.memory_scan_complete ? "yes" : "no") << "\n";
        for (const auto& finding : result.findings) print_finding(finding);
        std::cout << "\nHeuristic results only; findings require manual validation.\n";
    }
    return result.memory_scan_complete ? 0 : 3;
}
