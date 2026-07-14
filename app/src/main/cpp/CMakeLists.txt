cmake_minimum_required(VERSION 3.22.1)

project("ApkGuard")

add_library(
        ApkGuard
        SHARED
        GuardVMP.cpp
        sha256.cpp
        GuardDexLoader.cpp
        GuardEnvGuard.cpp
        GuardSelfHash.cpp
        VmpRuntime.cpp
        VmpParser.cpp
        VmpInterpreter.cpp
        VmContext.cpp
        VmHandlers.cpp
        VmOpcodeHandler.cpp
)

target_compile_options(
        ApkGuard
        PRIVATE
        -O2
        -DNDEBUG
        -fvisibility=hidden
        -fvisibility-inlines-hidden
        -ffunction-sections
        -fdata-sections
        -fno-exceptions
        -fno-rtti
)

target_link_options(
        ApkGuard
        PRIVATE
        "-Wl,--gc-sections"
        "-Wl,--strip-all"
        "-Wl,-z,relro"
        "-Wl,-z,now"
        "-Wl,-z,noexecstack"
        "-Wl,-z,max-page-size=16384"
)

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(
        ApkGuard
        ${log-lib}
        ${android-lib}
)

add_library(
        GuardTool
        SHARED
        GuardTool.cpp
)

target_compile_options(
        GuardTool
        PRIVATE
        -O2
        -DNDEBUG
        -fvisibility=hidden
        -fvisibility-inlines-hidden
        -ffunction-sections
        -fdata-sections
        -fno-exceptions
        -fno-rtti
)

target_link_options(
        GuardTool
        PRIVATE
        "-Wl,--gc-sections"
        "-Wl,--strip-all"
        "-Wl,-z,relro"
        "-Wl,-z,now"
        "-Wl,-z,noexecstack"
        "-Wl,-z,max-page-size=16384"
)

target_link_libraries(
        GuardTool
        ${log-lib}
        ${android-lib}
)
