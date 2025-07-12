cmake_minimum_required(VERSION 3.16)
project(GarudaHS VERSION 1.2.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific options
if(MSVC)
    add_compile_options(/W4 /WX /permissive-)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_compile_definitions(WIN32_LEAN_AND_MEAN)
    add_compile_definitions(NOMINMAX)
    
    # Security flags
    add_compile_options(/GS /sdl /guard:cf)
    add_link_options(/GUARD:CF /DYNAMICBASE /NXCOMPAT)
    
    # Optimization flags for Release
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/O2 /Ob2 /DNDEBUG)
        add_link_options(/OPT:REF /OPT:ICF)
    endif()
endif()

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})

# GarudaHS Client Library
set(CLIENT_SOURCES
    GarudaHS_Client/src/pch.cpp
    GarudaHS_Client/src/dllmain.cpp
    GarudaHS_Client/src/GarudaHS_StaticCore.cpp
    GarudaHS_Client/src/EnhancedAntiCheatCore.cpp
    GarudaHS_Client/src/ProcessWatcher.cpp
    GarudaHS_Client/src/AntiDebug.cpp
    GarudaHS_Client/src/InjectionScanner.cpp
    GarudaHS_Client/src/MemorySignatureScanner.cpp
    GarudaHS_Client/src/WindowDetector.cpp
    GarudaHS_Client/src/AntiSuspendThreads.cpp
    GarudaHS_Client/src/OverlayScanner.cpp
    GarudaHS_Client/src/Logger.cpp
    GarudaHS_Client/src/ConfigManager.cpp
    GarudaHS_Client/src/SecurityUtils.cpp
    GarudaHS_Client/src/LayeredDetection.cpp
    GarudaHS_Client/src/EnhancedSignatureDetector.cpp
    GarudaHS_Client/src/HeuristicMemoryScanner.cpp
    GarudaHS_Client/src/ThreadInjectionTracer.cpp
    GarudaHS_Client/src/EnhancedModuleBlacklist.cpp
    GarudaHS_Client/src/DynamicBehaviorDetector.cpp
    GarudaHS_Client/src/FileIntegrityChecker.cpp
)

set(CLIENT_HEADERS
    GarudaHS_Client/include/pch.h
    GarudaHS_Client/include/GarudaHS_StaticCore.h
    GarudaHS_Client/include/EnhancedAntiCheatCore.h
    GarudaHS_Client/include/ProcessWatcher.h
    GarudaHS_Client/include/AntiDebug.h
    GarudaHS_Client/include/InjectionScanner.h
    GarudaHS_Client/include/MemorySignatureScanner.h
    GarudaHS_Client/include/WindowDetector.h
    GarudaHS_Client/include/AntiSuspendThreads.h
    GarudaHS_Client/include/OverlayScanner.h
    GarudaHS_Client/include/Logger.h
    GarudaHS_Client/include/ConfigManager.h
    GarudaHS_Client/include/SecurityUtils.h
    GarudaHS_Client/include/LayeredDetection.h
    GarudaHS_Client/include/EnhancedSignatureDetector.h
    GarudaHS_Client/include/HeuristicMemoryScanner.h
    GarudaHS_Client/include/ThreadInjectionTracer.h
    GarudaHS_Client/include/EnhancedModuleBlacklist.h
    GarudaHS_Client/include/DynamicBehaviorDetector.h
    GarudaHS_Client/include/FileIntegrityChecker.h
)

# Create client library
add_library(GarudaHS_Client SHARED ${CLIENT_SOURCES} ${CLIENT_HEADERS})

# Set precompiled headers
target_precompile_headers(GarudaHS_Client PRIVATE GarudaHS_Client/include/pch.h)

# Link libraries for client
target_link_libraries(GarudaHS_Client
    PRIVATE
    kernel32
    user32
    advapi32
    shell32
    ole32
    oleaut32
    uuid
    odbc32
    odbccp32
    psapi
    version
    wintrust
    crypt32
    ws2_32
    ${OPENSSL_LIBRARIES}
)

# Set client properties
set_target_properties(GarudaHS_Client PROPERTIES
    OUTPUT_NAME "GarudaHS_Client"
    SUFFIX ".dll"
    PREFIX ""
)

# GarudaHS Server Executable
set(SERVER_SOURCES
    GarudaHS_Server/src/main.cpp
    GarudaHS_Server/src/server.cpp
    GarudaHS_Server/src/FileIntegrityValidator.cpp
)

set(SERVER_HEADERS
    GarudaHS_Server/include/server.h
    GarudaHS_Server/include/FileIntegrityValidator.h
)

# Create server executable
add_executable(GarudaHS_Server ${SERVER_SOURCES} ${SERVER_HEADERS})

# Link libraries for server
target_link_libraries(GarudaHS_Server
    PRIVATE
    kernel32
    user32
    ws2_32
    ${OPENSSL_LIBRARIES}
    ${JSONCPP_LIBRARIES}
)

# Set server properties
set_target_properties(GarudaHS_Server PROPERTIES
    OUTPUT_NAME "GarudaHS_Server"
    SUFFIX ".exe"
)

# Test executables
option(BUILD_TESTS "Build test executables" ON)

if(BUILD_TESTS)
    # File Integrity Checker Tests
    add_executable(TestFileIntegrityChecker
        GarudaHS_Client/tests/TestFileIntegrityChecker.cpp
        GarudaHS_Client/src/FileIntegrityChecker.cpp
        GarudaHS_Client/src/Logger.cpp
    )
    
    target_link_libraries(TestFileIntegrityChecker
        PRIVATE
        kernel32
        user32
        advapi32
        crypt32
        ${OPENSSL_LIBRARIES}
    )
    
    target_include_directories(TestFileIntegrityChecker
        PRIVATE
        GarudaHS_Client/include
    )

    # Client-Server Integration Tests
    add_executable(TestClientServerIntegration
        GarudaHS_Client/tests/TestClientServerIntegration.cpp
        GarudaHS_Client/src/FileIntegrityChecker.cpp
        GarudaHS_Client/src/Logger.cpp
    )
    
    target_link_libraries(TestClientServerIntegration
        PRIVATE
        kernel32
        user32
        advapi32
        crypt32
        ws2_32
        ${OPENSSL_LIBRARIES}
        ${JSONCPP_LIBRARIES}
    )
    
    target_include_directories(TestClientServerIntegration
        PRIVATE
        GarudaHS_Client/include
    )
endif()

# Installation
install(TARGETS GarudaHS_Client
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(TARGETS GarudaHS_Server
    RUNTIME DESTINATION bin
)

install(FILES
    GarudaHS_Client/file_integrity_database.json
    GarudaHS_Server/config/server_config.json
    DESTINATION config
)

install(DIRECTORY
    GarudaHS_Client/docs/
    DESTINATION docs
)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "GarudaHS")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "GarudaHS Anti-Cheat System")
set(CPACK_PACKAGE_VENDOR "GarudaHS Development Team")
set(CPACK_PACKAGE_CONTACT "support@garudahs.com")

set(CPACK_GENERATOR "ZIP;NSIS")
set(CPACK_SOURCE_GENERATOR "ZIP")

set(CPACK_NSIS_DISPLAY_NAME "GarudaHS Anti-Cheat System")
set(CPACK_NSIS_PACKAGE_NAME "GarudaHS")
set(CPACK_NSIS_CONTACT "support@garudahs.com")
set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/garudahs/garudahs")

include(CPack)

# Custom targets
add_custom_target(format
    COMMAND clang-format -i ${CLIENT_SOURCES} ${CLIENT_HEADERS} ${SERVER_SOURCES} ${SERVER_HEADERS}
    COMMENT "Formatting source code"
)

add_custom_target(docs
    COMMAND doxygen Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Generating documentation"
)

# Print configuration summary
message(STATUS "")
message(STATUS "GarudaHS Configuration Summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  OpenSSL found: ${OPENSSL_FOUND}")
message(STATUS "  JsonCpp found: ${JSONCPP_FOUND}")
message(STATUS "")
