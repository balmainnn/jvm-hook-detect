# jvm-hook-detect

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D4.svg)](https://learn.microsoft.com/windows/)
[![API](https://img.shields.io/badge/API-Win32-5C2D91.svg)](https://learn.microsoft.com/windows/win32/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A small, read-only Windows utility for gathering **heuristic** evidence about running Java processes, including Minecraft Java Edition. It enumerates Java processes and loaded modules, reports executable memory regions not covered by an enumerated module, and records a conservative JVM-export inspection note.

> **Important:** this is a triage aid, not a malware verdict, anti-cheat certification, or proof that a process is clean. JVM JIT compilers legitimately create executable memory, and module enumeration can be incomplete due to permissions, architecture, or process churn.

## Features

- Enumerate `java.exe` and `javaw.exe` processes with PID and executable path.
- Open target processes with read-only `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` access.
- Enumerate loaded modules using PSAPI and report module names, paths, base addresses, and image sizes.
- Walk virtual memory using `VirtualQueryEx`.
- Flag committed executable regions not covered by the enumerated module ranges; distinguish writable-executable regions as higher-priority heuristics.
- Inspect the expected `JNI_GetCreatedJavaVMs` export address in `jvm.dll` without executing code in the target.
- Print severity-coded CLI findings and export a JSON report.

## Scope and limitations

The utility does **not** inject code, load a Java agent, suspend threads, change target memory, or attempt to discover opaque `JNIEnv`/`JavaVM` table instances from an external process. JNI table instances are runtime-owned structures and cannot be reliably inferred from module exports alone. The export check is intentionally conservative: sampling bytes is not enough to declare an inline hook. Reliable hook attribution requires architecture-aware disassembly, matching module/build identities, and handling legitimate instrumentation.

A process may contain executable memory that is legitimate (JIT-generated code, JVM internals, profilers, debuggers, graphics drivers, or security software). Likewise, a malicious mapping may evade these simple heuristics. Treat results as leads for manual review.

## Build

Requirements:
- Windows 10/11
- Visual Studio 2022 with **Desktop development with C++**
- CMake 3.20 or newer
- A matching-architecture build environment for the target process is recommended

### Visual Studio Developer PowerShell

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Executable: `build\Release\jvm-hook-detect.exe`

### Visual Studio IDE

Open the folder containing `CMakeLists.txt` in Visual Studio, select an x64 configuration, and build the `jvm-hook-detect` target.

## Usage

List Java processes:

```powershell
.\jvm-hook-detect.exe --list
```

Scan a specific PID:

```powershell
.\jvm-hook-detect.exe --pid 12345
```

Emit JSON to standard output:

```powershell
.\jvm-hook-detect.exe --pid 12345 --json
```

Save a JSON report using PowerShell redirection:

```powershell
.\jvm-hook-detect.exe --pid 12345 --json > report.json
```

Exit codes:
- `0`: scan completed, or process list displayed
- `1`: no Java processes found when listing
- `2`: invalid arguments or PID not found
- `3`: scan was incomplete due to access or memory-query limitations

## Example output

```text
Scanning javaw.exe (PID 12345)
Enumerated modules: 87, scan complete: yes
[WARNING] unbacked-executable-region: Executable region not covered by an enumerated module at 0x000001F0000000. Heuristic only; JIT runtimes can legitimately allocate executable memory.
[INFO] jvm-export-sampled: Read 16 bytes at the expected JNI_GetCreatedJavaVMs export address. Raw bytes are not classified as a hook without build-aware disassembly.

Heuristic results only; findings require manual validation.
```

Addresses, module counts, and findings above are illustrative.

## Operational guidance

- Scan only processes you own or are authorized to inspect.
- If access is denied, rerun from an elevated terminal only when you have authorization.
- Preserve the JSON report and compare against a known-good baseline for the same JVM distribution and version.
- Validate suspicious regions with trusted tools and corroborating telemetry before drawing conclusions.
- Keep the tool updated and test it across supported Windows and JDK versions before relying on it operationally.

## Technical disclaimer

Memory layouts and exported symbols vary by JDK vendor, version, architecture, and runtime flags. `VirtualQueryEx` and PSAPI observations are snapshots and can race with allocation/unload activity. The scanner does not establish intent, and its severity labels express heuristic priority rather than certainty. This project is intended for defensive diagnostics, incident response, and authorized security research.

## License

MIT. See [LICENSE](LICENSE).
