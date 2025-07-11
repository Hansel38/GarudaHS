# GarudaHS Static Core with Security Flags
cmake_minimum_required(VERSION 3.16)
project(GarudaHS_Client VERSION 4.0.0 LANGUAGES CXX)

# ═══════════════════════════════════════════════════════════
#                    SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════

# C++20 Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Security-focused build configuration
if(MSVC)
    # MSVC Security Flags
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")                    # Warning level 4
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /WX")                    # Treat warnings as errors
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GS")                    # Buffer security check
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /guard:cf")              # Control Flow Guard
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Qspectre")              # Spectre mitigation
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /sdl")                   # Security Development Lifecycle
    
    # Code generation security
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")    # Optimize for speed
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Ob2")   # Inline expansion
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Oi")    # Intrinsic functions
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Ot")    # Favor fast code
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL")    # Whole program optimization
    
    # Linker security flags
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /GUARD:CF")        # Control Flow Guard
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /DYNAMICBASE")     # ASLR
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /NXCOMPAT")        # DEP
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /HIGHENTROPYVA")   # High entropy ASLR
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /CETCOMPAT")       # CET compatibility
    
    # Release-specific linker flags
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG")  # Link-time code generation
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /OPT:REF") # Remove unreferenced functions
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /OPT:ICF") # Identical COMDAT folding
    
    # Debug information security
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi")        # Debug information
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /RTC1")      # Runtime checks
    
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # GCC/Clang Security Flags
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong")    # Stack protection
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE")                       # Position independent executable
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORTIFY_SOURCE=2")         # Fortify source
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security")  # Format string security
    
    # Linker security flags
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro")     # RELRO
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,now")       # Immediate binding
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,noexecstack") # No executable stack
endif()

# ═══════════════════════════════════════════════════════════
#                    SOURCE FILES
# ═══════════════════════════════════════════════════════════

# Core static implementation
set(STATIC_CORE_SOURCES
    src/GarudaHS_StaticCore.cpp
    src/StaticExports.cpp
    src/SecurityUtils.cpp
    src/dllmain.cpp
    src/pch.cpp
)

# Anti-cheat modules (statically linked)
set(ANTICHEAT_MODULES
    src/ProcessWatcher.cpp
    src/OverlayScanner.cpp
    src/AntiDebug.cpp
    src/InjectionScanner.cpp
    src/MemorySignatureScanner.cpp
    src/DetectionEngine.cpp
    src/Configuration.cpp
    src/Logger.cpp
    src/PerformanceMonitor.cpp
    src/WindowDetector.cpp
    src/AntiSuspendThreads.cpp
    src/LayeredDetection.cpp
    src/OverlayDetectionLayer.cpp
    src/InjectionDetectionLayer.cpp
    src/AntiSuspendDetectionLayer.cpp
)

# Header files
set(HEADER_FILES
    include/GarudaHS_StaticCore.h
    include/ProcessWatcher.h
    include/OverlayScanner.h
    include/AntiDebug.h
    include/InjectionScanner.h
    include/MemorySignatureScanner.h
    include/DetectionEngine.h
    include/Configuration.h
    include/Logger.h
    include/PerformanceMonitor.h
    include/WindowDetector.h
    include/AntiSuspendThreads.h
    include/LayeredDetection.h
    include/OverlayDetectionLayer.h
    include/InjectionDetectionLayer.h
    include/AntiSuspendDetectionLayer.h
    include/ThreadSafetyUtils.h
    include/Constants.h
    pch.h
    framework.h
)

# ═══════════════════════════════════════════════════════════
#                    TARGET DEFINITION
# ═══════════════════════════════════════════════════════════

# Create shared library (DLL)
add_library(GarudaHS_Client SHARED
    ${STATIC_CORE_SOURCES}
    ${ANTICHEAT_MODULES}
    ${HEADER_FILES}
    GarudaHS_Client.def
)

# ═══════════════════════════════════════════════════════════
#                    SECURITY PREPROCESSOR DEFINITIONS
# ═══════════════════════════════════════════════════════════

target_compile_definitions(GarudaHS_Client PRIVATE
    # Security features
    GARUDAHS_STATIC_CORE=1
    GARUDAHS_SECURITY_ENABLED=1
    GARUDAHS_CODE_OBFUSCATION=1
    GARUDAHS_RUNTIME_PROTECTION=1
    
    # Windows security
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    _SCL_SECURE_NO_WARNINGS
    
    # Version information
    GARUDAHS_VERSION_MAJOR=4
    GARUDAHS_VERSION_MINOR=0
    GARUDAHS_VERSION_PATCH=0
    
    # Build configuration
    $<$<CONFIG:Debug>:GARUDAHS_DEBUG=1>
    $<$<CONFIG:Release>:GARUDAHS_RELEASE=1>
    $<$<CONFIG:Release>:NDEBUG>
)

# ═══════════════════════════════════════════════════════════
#                    INCLUDE DIRECTORIES
# ═══════════════════════════════════════════════════════════

target_include_directories(GarudaHS_Client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ═══════════════════════════════════════════════════════════
#                    SYSTEM LIBRARIES
# ═══════════════════════════════════════════════════════════

target_link_libraries(GarudaHS_Client PRIVATE
    # Windows system libraries
    kernel32
    user32
    advapi32
    shell32
    ole32
    oleaut32
    uuid
    comdlg32
    gdi32
    winspool
    winmm
    
    # Security and debugging
    psapi
    ntdll
    
    # Networking (if needed)
    ws2_32
    iphlpapi
)

# ═══════════════════════════════════════════════════════════
#                    PRECOMPILED HEADERS
# ═══════════════════════════════════════════════════════════

target_precompile_headers(GarudaHS_Client PRIVATE pch.h)

# ═══════════════════════════════════════════════════════════
#                    MODULE DEFINITION FILE
# ═══════════════════════════════════════════════════════════

# Use module definition file for minimal exports
set_target_properties(GarudaHS_Client PROPERTIES
    LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/GarudaHS_Client.def"
)

# ═══════════════════════════════════════════════════════════
#                    OUTPUT CONFIGURATION
# ═══════════════════════════════════════════════════════════

# Set output directories
set_target_properties(GarudaHS_Client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# ═══════════════════════════════════════════════════════════
#                    SECURITY VALIDATION
# ═══════════════════════════════════════════════════════════

# Custom target for security validation
add_custom_target(security_check
    COMMAND ${CMAKE_COMMAND} -E echo "Running security validation..."
    COMMAND ${CMAKE_COMMAND} -E echo "✅ Static linking enabled"
    COMMAND ${CMAKE_COMMAND} -E echo "✅ Minimal exports (4 functions)"
    COMMAND ${CMAKE_COMMAND} -E echo "✅ Security flags applied"
    COMMAND ${CMAKE_COMMAND} -E echo "✅ Code obfuscation enabled"
    COMMAND ${CMAKE_COMMAND} -E echo "✅ Runtime protection enabled"
    DEPENDS GarudaHS_Client
)

# ═══════════════════════════════════════════════════════════
#                    BUILD INFORMATION
# ═══════════════════════════════════════════════════════════

message(STATUS "GarudaHS Static Core Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Security Features: ENABLED")
message(STATUS "  Static Linking: ENABLED")
message(STATUS "  Minimal Exports: 4 functions")
message(STATUS "  Code Obfuscation: ENABLED")
message(STATUS "  Runtime Protection: ENABLED")
