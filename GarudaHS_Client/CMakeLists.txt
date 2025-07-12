cmake_minimum_required(VERSION 3.20)

# Project configuration
project(GarudaHS_Enhanced 
    VERSION 3.5.0
    DESCRIPTION "GarudaHS Enhanced Anti-Cheat System"
    LANGUAGES CXX)

# Set C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Platform-specific settings
if(WIN32)
    # Windows-specific settings
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    add_definitions(-D_WIN32_WINNT=0x0601) # Windows 7+
    
    # Enable static linking for MSVC
    if(MSVC)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        add_compile_options(/W4 /WX- /permissive-)
        add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    endif()
else()
    message(FATAL_ERROR "GarudaHS Enhanced is currently Windows-only")
endif()

# Source files organization
set(ENHANCED_HEADERS
    include/EnhancedAntiCheatCore.h
    include/EnhancedSignatureDetector.h
    include/HeuristicMemoryScanner.h
    include/ThreadInjectionTracer.h
    include/EnhancedModuleBlacklist.h
    include/DynamicBehaviorDetector.h
)

set(ENHANCED_SOURCES
    src/EnhancedAntiCheatCore.cpp
    src/EnhancedSignatureDetector.cpp
    src/HeuristicMemoryScanner.cpp
    src/ThreadInjectionTracer.cpp
    src/EnhancedModuleBlacklist.cpp
    src/DynamicBehaviorDetector.cpp
)

set(CORE_HEADERS
    include/AntiDebug.h
    include/AntiSuspendThreads.h
    include/Configuration.h
    include/DetectionEngine.h
    include/GarudaHS_Exports.h
    include/GarudaHS_StaticCore.h
    include/InjectionScanner.h
    include/Logger.h
    include/MemorySignatureScanner.h
    include/OverlayScanner.h
    include/ProcessWatcher.h
    include/SecurityUtils.h
    include/ThreadSafetyUtils.h
    include/WindowDetector.h
)

set(CORE_SOURCES
    src/AntiDebug.cpp
    src/AntiSuspendThreads.cpp
    src/Configuration.cpp
    src/DetectionEngine.cpp
    src/GarudaHS_StaticCore.cpp
    src/InjectionScanner.cpp
    src/Logger.cpp
    src/MemorySignatureScanner.cpp
    src/OverlayScanner.cpp
    src/ProcessWatcher.cpp
    src/SecurityUtils.cpp
    src/StaticExports.cpp
    src/ThreadInjectionTracer.cpp
    src/WindowDetector.cpp
)

# Create static library
add_library(GarudaHS_Enhanced_Static STATIC
    ${ENHANCED_HEADERS}
    ${ENHANCED_SOURCES}
    ${CORE_HEADERS}
    ${CORE_SOURCES}
)

# Create shared library (DLL)
add_library(GarudaHS_Enhanced_Shared SHARED
    ${ENHANCED_HEADERS}
    ${ENHANCED_SOURCES}
    ${CORE_HEADERS}
    ${CORE_SOURCES}
)

# Set target properties
set_target_properties(GarudaHS_Enhanced_Static PROPERTIES
    OUTPUT_NAME "GarudaHS_Enhanced"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

set_target_properties(GarudaHS_Enhanced_Shared PROPERTIES
    OUTPUT_NAME "GarudaHS_Enhanced"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# Include directories
target_include_directories(GarudaHS_Enhanced_Static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_include_directories(GarudaHS_Enhanced_Shared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Link libraries
if(WIN32)
    set(WINDOWS_LIBS
        kernel32
        user32
        gdi32
        winspool
        shell32
        ole32
        oleaut32
        uuid
        comdlg32
        advapi32
        psapi
        wintrust
        crypt32
        d3d9
        d3d11
        dxgi
        opengl32
    )
    
    target_link_libraries(GarudaHS_Enhanced_Static PRIVATE ${WINDOWS_LIBS})
    target_link_libraries(GarudaHS_Enhanced_Shared PRIVATE ${WINDOWS_LIBS})
endif()

# Compiler-specific options
if(MSVC)
    target_compile_options(GarudaHS_Enhanced_Static PRIVATE
        /W4          # Warning level 4
        /WX-         # Don't treat warnings as errors
        /permissive- # Disable non-conforming code
        /Zc:__cplusplus # Enable correct __cplusplus macro
    )
    
    target_compile_options(GarudaHS_Enhanced_Shared PRIVATE
        /W4
        /WX-
        /permissive-
        /Zc:__cplusplus
    )
    
    # Enable precompiled headers for faster compilation
    if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.16")
        target_precompile_headers(GarudaHS_Enhanced_Static PRIVATE
            <windows.h>
            <string>
            <vector>
            <memory>
            <mutex>
            <atomic>
            <functional>
        )
        
        target_precompile_headers(GarudaHS_Enhanced_Shared REUSE_FROM GarudaHS_Enhanced_Static)
    endif()
endif()

# Configuration-specific settings
target_compile_definitions(GarudaHS_Enhanced_Static PRIVATE
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
)

target_compile_definitions(GarudaHS_Enhanced_Shared PRIVATE
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
    GARUDAHS_EXPORTS
)

# Examples and tests (optional)
option(BUILD_EXAMPLES "Build example applications" ON)
option(BUILD_TESTS "Build test applications" ON)

if(BUILD_EXAMPLES)
    add_executable(EnhancedAntiCheatExample
        examples/EnhancedAntiCheatExample.cpp
    )
    
    target_link_libraries(EnhancedAntiCheatExample PRIVATE
        GarudaHS_Enhanced_Static
    )
    
    set_target_properties(EnhancedAntiCheatExample PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples"
    )
endif()

if(BUILD_TESTS)
    add_executable(TestEnhancedFeatures
        tests/test_enhanced_features.cpp
    )
    
    target_link_libraries(TestEnhancedFeatures PRIVATE
        GarudaHS_Enhanced_Static
    )
    
    set_target_properties(TestEnhancedFeatures PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
    
    # Enable testing
    enable_testing()
    add_test(NAME EnhancedFeaturesTest COMMAND TestEnhancedFeatures)
endif()

# Installation
install(TARGETS GarudaHS_Enhanced_Static GarudaHS_Enhanced_Shared
    EXPORT GarudaHSTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES ${ENHANCED_HEADERS} ${CORE_HEADERS}
    DESTINATION include/GarudaHS
)

install(FILES
    config/enhanced_config.json
    detection_rules.json
    garudahs_config.ini
    memory_scanner_config.ini
    memory_signatures.json
    messages.json
    DESTINATION config
)

install(FILES
    docs/API_Reference_Enhanced.md
    README_Enhanced.md
    DESTINATION docs
)

# Export configuration
install(EXPORT GarudaHSTargets
    FILE GarudaHSTargets.cmake
    NAMESPACE GarudaHS::
    DESTINATION lib/cmake/GarudaHS
)

# Create config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/GarudaHSConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GarudaHSConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/GarudaHSConfig.cmake"
    INSTALL_DESTINATION lib/cmake/GarudaHS
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/GarudaHSConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/GarudaHSConfigVersion.cmake"
    DESTINATION lib/cmake/GarudaHS
)

# Print configuration summary
message(STATUS "")
message(STATUS "GarudaHS Enhanced Anti-Cheat System v${PROJECT_VERSION}")
message(STATUS "========================================")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Build examples: ${BUILD_EXAMPLES}")
message(STATUS "Build tests: ${BUILD_TESTS}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "Enhanced Features:")
message(STATUS "  ✅ Enhanced Signature Pattern Detection")
message(STATUS "  ✅ Heuristic Memory Scanner")
message(STATUS "  ✅ Thread Injection Tracer")
message(STATUS "  ✅ Enhanced Module Blacklist")
message(STATUS "  ✅ Dynamic Behavior Detector")
message(STATUS "  ✅ Enhanced Anti-Cheat Core Integration")
message(STATUS "========================================")
message(STATUS "")
