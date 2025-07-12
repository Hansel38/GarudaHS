@echo off
echo ========================================
echo  GarudaHS File Integrity Server
echo  Starting Validation Server...
echo ========================================
echo.

REM Check if server executable exists
if not exist "..\Release\GarudaHS_Server.exe" (
    echo ERROR: Server executable not found!
    echo Please build the server first using Visual Studio.
    echo Expected location: ..\Release\GarudaHS_Server.exe
    pause
    exit /b 1
)

REM Create necessary directories
if not exist "..\logs" mkdir "..\logs"
if not exist "..\data" mkdir "..\data"
if not exist "..\config" mkdir "..\config"
if not exist "..\certs" mkdir "..\certs"

REM Check if config file exists
if not exist "..\config\server_config.json" (
    echo WARNING: Server config file not found!
    echo Creating default configuration...
    copy "server_config.json" "..\config\server_config.json" >nul 2>&1
)

REM Check if integrity database exists
if not exist "..\data\integrity_database.json" (
    echo WARNING: Integrity database not found!
    echo Creating default database...
    copy "..\GarudaHS_Client\file_integrity_database.json" "..\data\integrity_database.json" >nul 2>&1
)

echo Starting GarudaHS File Integrity Validation Server...
echo.
echo Server Configuration:
echo - Port: 8443 (HTTPS)
echo - Max Connections: 1000
echo - SSL: Enabled
echo - Rate Limiting: Enabled
echo - Session Timeout: 30 minutes
echo.

REM Change to server directory
cd /d "%~dp0\.."

REM Start the server
echo [%date% %time%] Starting server...
Release\GarudaHS_Server.exe

REM Check exit code
if %ERRORLEVEL% EQU 0 (
    echo.
    echo [%date% %time%] Server stopped gracefully.
) else (
    echo.
    echo [%date% %time%] Server stopped with error code: %ERRORLEVEL%
)

echo.
echo Press any key to exit...
pause >nul
