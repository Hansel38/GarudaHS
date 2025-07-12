@echo off
setlocal enabledelayedexpansion

echo ========================================
echo  GarudaHS Anti-Cheat Build System
echo  Version 1.2+ with File Integrity Check
echo ========================================
echo.

REM Check if CMake is available
cmake --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake not found in PATH
    echo Please install CMake and add it to your PATH
    echo Download from: https://cmake.org/download/
    pause
    exit /b 1
)

REM Check if Visual Studio is available
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Setting up Visual Studio environment...
    
    REM Try to find Visual Studio 2022
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    ) else (
        echo ERROR: Visual Studio 2022 not found
        echo Please install Visual Studio 2022 with C++ development tools
        pause
        exit /b 1
    )
)

REM Set build configuration
set BUILD_TYPE=Release
set BUILD_TESTS=ON
set BUILD_DIR=build

REM Parse command line arguments
:parse_args
if "%1"=="" goto :done_parsing
if /i "%1"=="debug" set BUILD_TYPE=Debug
if /i "%1"=="release" set BUILD_TYPE=Release
if /i "%1"=="notests" set BUILD_TESTS=OFF
if /i "%1"=="clean" (
    echo Cleaning build directory...
    if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
    echo Build directory cleaned.
    goto :end
)
shift
goto :parse_args
:done_parsing

echo Build Configuration:
echo - Build Type: %BUILD_TYPE%
echo - Build Tests: %BUILD_TESTS%
echo - Build Directory: %BUILD_DIR%
echo.

REM Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

REM Change to build directory
cd %BUILD_DIR%

echo Configuring project with CMake...
cmake .. -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DBUILD_TESTS=%BUILD_TESTS% ^
    -DCMAKE_INSTALL_PREFIX=../install

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake configuration failed
    cd ..
    pause
    exit /b 1
)

echo.
echo Building project...
cmake --build . --config %BUILD_TYPE% --parallel

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed
    cd ..
    pause
    exit /b 1
)

echo.
echo Build completed successfully!
echo.

REM Show build results
echo Build Results:
if exist "%BUILD_TYPE%\GarudaHS_Client.dll" (
    echo [✓] GarudaHS_Client.dll - Client library built successfully
) else (
    echo [✗] GarudaHS_Client.dll - Client library build failed
)

if exist "%BUILD_TYPE%\GarudaHS_Server.exe" (
    echo [✓] GarudaHS_Server.exe - Server executable built successfully
) else (
    echo [✗] GarudaHS_Server.exe - Server executable build failed
)

if "%BUILD_TESTS%"=="ON" (
    if exist "%BUILD_TYPE%\TestFileIntegrityChecker.exe" (
        echo [✓] TestFileIntegrityChecker.exe - Test executable built successfully
    ) else (
        echo [✗] TestFileIntegrityChecker.exe - Test executable build failed
    )
    
    if exist "%BUILD_TYPE%\TestClientServerIntegration.exe" (
        echo [✓] TestClientServerIntegration.exe - Integration test built successfully
    ) else (
        echo [✗] TestClientServerIntegration.exe - Integration test build failed
    )
)

echo.
echo Output files location: %CD%\%BUILD_TYPE%\
echo.

REM Ask if user wants to run tests
if "%BUILD_TESTS%"=="ON" (
    set /p run_tests="Do you want to run tests? (y/n): "
    if /i "!run_tests!"=="y" (
        echo.
        echo Running File Integrity Checker tests...
        if exist "%BUILD_TYPE%\TestFileIntegrityChecker.exe" (
            "%BUILD_TYPE%\TestFileIntegrityChecker.exe"
        )
        
        echo.
        echo Running Client-Server Integration tests...
        if exist "%BUILD_TYPE%\TestClientServerIntegration.exe" (
            "%BUILD_TYPE%\TestClientServerIntegration.exe"
        )
    )
)

REM Ask if user wants to install
set /p install_files="Do you want to install files? (y/n): "
if /i "!install_files!"=="y" (
    echo.
    echo Installing files...
    cmake --install . --config %BUILD_TYPE%
    
    if %ERRORLEVEL% EQU 0 (
        echo Installation completed successfully!
        echo Files installed to: ..\install\
    ) else (
        echo Installation failed!
    )
)

cd ..

:end
echo.
echo Build script completed.
echo.
echo Usage: build.bat [options]
echo Options:
echo   debug     - Build in Debug mode
echo   release   - Build in Release mode (default)
echo   notests   - Skip building tests
echo   clean     - Clean build directory
echo.
echo Examples:
echo   build.bat              - Build in Release mode with tests
echo   build.bat debug        - Build in Debug mode with tests
echo   build.bat release notests - Build in Release mode without tests
echo   build.bat clean        - Clean build directory
echo.
pause
