#pragma once
#include "scanner.h"

namespace jhd {
// Performs conservative, read-only checks around the exported JNI_GetCreatedJavaVMs
// entry point and the module that owns it. This does not assume that JNI tables
// can be reliably discovered from outside the JVM; no remote code is executed.
void inspect_jvm_exports(const Process& process,
                         const std::vector<ModuleInfo>& modules,
                         std::vector<Finding>& findings);
}
