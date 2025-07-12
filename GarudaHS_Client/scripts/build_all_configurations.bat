@echo off
setlocal enabledelayedexpansion

echo ================================================================
echo GarudaHS Enhanced Anti-Cheat System v3.5+
echo Comprehensive Build Script - All Configurations
echo ================================================================
echo.

REM Set solution file
set SOLUTION_FILE=..\GarudaHS.sln
set PROJECT_NAME=GarudaHS_Client

REM Check if Visual Studio is available
where msbuild >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: MSBuild not found in PATH
    echo.
    echo Please run this script from one of the following:
    echo - Visual Studio Developer Command Prompt
    echo - Visual Studio Developer PowerShell
    echo - After running vcvarsall.bat
    echo.
    echo Or ensure Visual Studio Build Tools are installed
    pause
    exit /b 1
)

echo Visual Studio Build Tools detected
echo Solution: %SOLUTION_FILE%
echo Project: %PROJECT_NAME%
echo.

REM Build configurations
set CONFIGS=Debug Release
set PLATFORMS=x86 x64

echo Building all configurations...
echo.

set BUILD_SUCCESS=0
set BUILD_FAILED=0

for %%C in (%CONFIGS%) do (
    for %%P in (%PLATFORMS%) do (
        echo ----------------------------------------
        echo Building %%C ^| %%P
        echo ----------------------------------------
        
        REM Clean first
        echo Cleaning %%C ^| %%P...
        msbuild "%SOLUTION_FILE%" /p:Configuration=%%C /p:Platform=%%P /t:Clean /v:minimal /nologo
        
        REM Build
        echo Building %%C ^| %%P...
        msbuild "%SOLUTION_FILE%" /p:Configuration=%%C /p:Platform=%%P /v:minimal /nologo /m
        
        if !ERRORLEVEL! EQU 0 (
            echo ✅ SUCCESS: %%C ^| %%P
            set /a BUILD_SUCCESS+=1
            
            REM Check output files
            set OUTPUT_DIR=%%P\%%C
            if exist "!OUTPUT_DIR!\%PROJECT_NAME%.dll" (
                echo    DLL: !OUTPUT_DIR!\%PROJECT_NAME%.dll
                for %%I in ("!OUTPUT_DIR!\%PROJECT_NAME%.dll") do echo    Size: %%~zI bytes
            )
            if exist "!OUTPUT_DIR!\%PROJECT_NAME%.lib" (
                echo    LIB: !OUTPUT_DIR!\%PROJECT_NAME%.lib
                for %%I in ("!OUTPUT_DIR!\%PROJECT_NAME%.lib") do echo    Size: %%~zI bytes
            )
        ) else (
            echo ❌ FAILED: %%C ^| %%P
            set /a BUILD_FAILED+=1
        )
        echo.
    )
)

echo ================================================================
echo BUILD SUMMARY
echo ================================================================
echo Successful builds: %BUILD_SUCCESS%
echo Failed builds: %BUILD_FAILED%
echo.

if %BUILD_FAILED% GTR 0 (
    echo ⚠️  Some builds failed. Please check the error messages above.
    echo.
    echo Common issues and solutions:
    echo - Missing dependencies: Ensure wintrust.lib and crypt32.lib are available
    echo - C++20 standard: Verify project is set to C++20 standard
    echo - Include paths: Check that all include directories are properly set
    echo - Platform toolset: Ensure compatible platform toolset is selected
    echo.
) else (
    echo ✅ All builds completed successfully!
    echo.
    echo Enhanced Anti-Cheat Features Available:
    echo ✅ Enhanced Signature Pattern Detection
    echo ✅ Heuristic Memory Scanner
    echo ✅ Thread Injection Tracer  
    echo ✅ Enhanced Module Blacklist
    echo ✅ Dynamic Behavior Detector
    echo ✅ Enhanced Anti-Cheat Core Integration
    echo.
    echo Output directories:
    for %%C in (%CONFIGS%) do (
        for %%P in (%PLATFORMS%) do (
            echo   %%P\%%C\
        )
    )
)

echo.
echo Build script completed.
pause
