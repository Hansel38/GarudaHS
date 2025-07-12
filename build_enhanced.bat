@echo off
echo ================================================================
echo GarudaHS Enhanced Anti-Cheat System v3.5+ Build Script
echo ================================================================
echo.

REM Set build configuration
set BUILD_CONFIG=Release
set PLATFORM=x64
set SOLUTION_FILE=GarudaHS.sln

REM Check if Visual Studio is available
where msbuild >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: MSBuild not found in PATH
    echo Please run this script from Visual Studio Developer Command Prompt
    echo or ensure Visual Studio Build Tools are installed
    pause
    exit /b 1
)

echo Build Configuration: %BUILD_CONFIG%
echo Platform: %PLATFORM%
echo Solution File: %SOLUTION_FILE%
echo.

REM Clean previous build
echo Cleaning previous build...
msbuild "%SOLUTION_FILE%" /p:Configuration=%BUILD_CONFIG% /p:Platform=%PLATFORM% /t:Clean /v:minimal
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Clean failed
    pause
    exit /b 1
)

echo.
echo Building GarudaHS Enhanced Anti-Cheat System...
echo.

REM Build the solution
msbuild "%SOLUTION_FILE%" /p:Configuration=%BUILD_CONFIG% /p:Platform=%PLATFORM% /v:minimal /m
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ================================================================
    echo BUILD FAILED!
    echo ================================================================
    echo Please check the error messages above and fix any compilation issues.
    echo.
    echo Common issues:
    echo - Missing dependencies (wintrust.lib, crypt32.lib)
    echo - C++20 standard not enabled
    echo - Missing include directories
    echo - Syntax errors in enhanced system files
    echo.
    pause
    exit /b 1
)

echo.
echo ================================================================
echo BUILD SUCCESSFUL!
echo ================================================================
echo.

REM Check if output files exist
set OUTPUT_DIR=%PLATFORM%\%BUILD_CONFIG%
set DLL_FILE=%OUTPUT_DIR%\GarudaHS_Client.dll
set LIB_FILE=%OUTPUT_DIR%\GarudaHS_Client.lib

if exist "%DLL_FILE%" (
    echo ✅ DLL created: %DLL_FILE%
    for %%I in ("%DLL_FILE%") do echo    Size: %%~zI bytes
) else (
    echo ❌ DLL not found: %DLL_FILE%
)

if exist "%LIB_FILE%" (
    echo ✅ LIB created: %LIB_FILE%
    for %%I in ("%LIB_FILE%") do echo    Size: %%~zI bytes
) else (
    echo ❌ LIB not found: %LIB_FILE%
)

echo.
echo Enhanced Features Included:
echo ✅ Enhanced Signature Pattern Detection
echo ✅ Heuristic Memory Scanner
echo ✅ Thread Injection Tracer
echo ✅ Enhanced Module Blacklist
echo ✅ Dynamic Behavior Detector
echo ✅ Enhanced Anti-Cheat Core Integration
echo.

echo Build completed successfully!
echo Output directory: %OUTPUT_DIR%
echo.

REM Optional: Run example if requested
set /p RUN_EXAMPLE="Do you want to run the enhanced example? (y/n): "
if /i "%RUN_EXAMPLE%"=="y" (
    echo.
    echo Compiling and running enhanced example...
    
    REM Compile example
    cl /std:c++20 /EHsc /I"GarudaHS_Client\include" "GarudaHS_Client\examples\EnhancedAntiCheatExample.cpp" /link "%LIB_FILE%" user32.lib kernel32.lib psapi.lib wintrust.lib crypt32.lib /OUT:"enhanced_example.exe"
    
    if %ERRORLEVEL% EQU 0 (
        echo Example compiled successfully!
        echo Running enhanced example...
        echo.
        enhanced_example.exe
    ) else (
        echo Failed to compile example.
    )
)

echo.
echo ================================================================
echo GarudaHS Enhanced v3.5+ Build Complete
echo ================================================================
pause
