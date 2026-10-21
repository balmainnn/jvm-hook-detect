cmake_minimum_required(VERSION 3.20)
project(jvm-hook-detect VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "jvm-hook-detect currently supports Windows only.")
endif()

add_executable(jvm-hook-detect
  src/main.cpp
  src/process.cpp
  src/scanner.cpp
  src/jni_hook.cpp
)
target_include_directories(jvm-hook-detect PRIVATE include)
target_compile_features(jvm-hook-detect PRIVATE cxx_std_20)
target_compile_definitions(jvm-hook-detect PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
if(MSVC)
  target_compile_options(jvm-hook-detect PRIVATE /W4 /permissive- /EHsc /utf-8)
endif()
target_link_libraries(jvm-hook-detect PRIVATE Psapi)
