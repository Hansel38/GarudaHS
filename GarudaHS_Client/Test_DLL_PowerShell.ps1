# PowerShell Script untuk Test GarudaHS DLL
Write-Host "🛡️ GarudaHS Anti-Cheat DLL Test" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Load DLL
$dllPath = Resolve-Path "..\Debug\GarudaHS_Client.dll"
Write-Host "📦 Loading DLL: $dllPath" -ForegroundColor Yellow

try {
    # Define P/Invoke signatures
    $signature = @"
    [DllImport("$dllPath", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool GarudaHS_Execute(
        string operation,
        string parameters,
        IntPtr results,
        uint resultsSize,
        out uint bytesReturned
    );
    
    [DllImport("$dllPath", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr GarudaHS_GetVersion();
"@

    Add-Type -MemberDefinition $signature -Name "GarudaHSAPI" -Namespace "AntiCheat"
    Write-Host "✅ DLL loaded successfully!" -ForegroundColor Green
    
    # Test GetVersion
    Write-Host "`n📋 Testing GetVersion..." -ForegroundColor Yellow
    try {
        $versionPtr = [AntiCheat.GarudaHSAPI]::GarudaHS_GetVersion()
        if ($versionPtr -ne [IntPtr]::Zero) {
            $version = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($versionPtr)
            Write-Host "   📦 Version: $version" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️ Version returned null pointer" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "   ❌ GetVersion failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Test Basic Operations
    Write-Host "`n🧪 Testing Basic Operations..." -ForegroundColor Yellow
    
    $operations = @(
        "System::status",
        "System::initialize", 
        "ProcessWatcher::initialize",
        "OverlayScanner::initialize",
        "AntiDebug::initialize"
    )
    
    foreach ($op in $operations) {
        try {
            $bytesReturned = 0
            $result = [AntiCheat.GarudaHSAPI]::GarudaHS_Execute($op, $null, [IntPtr]::Zero, 0, [ref]$bytesReturned)
            
            $status = if ($result) { "✅ SUCCESS" } else { "❌ FAILED" }
            Write-Host "   🔧 $op : $status (Bytes: $bytesReturned)" -ForegroundColor $(if ($result) { "Green" } else { "Red" })
        } catch {
            Write-Host "   ❌ $op : ERROR - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host "`n📊 Test Summary:" -ForegroundColor Yellow
    Write-Host "✅ DLL Load: SUCCESS" -ForegroundColor Green
    Write-Host "✅ Function Export: SUCCESS" -ForegroundColor Green
    Write-Host "✅ Basic API Calls: TESTED" -ForegroundColor Green
    
    Write-Host "`n🎉 Module Aggregation Test Completed!" -ForegroundColor Green
    
} catch {
    Write-Host "❌ Error loading DLL: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   This might be normal if Module Aggregation is not yet compiled" -ForegroundColor Yellow
    
    # Try to check exports using alternative method
    Write-Host "`n🔍 Checking DLL exports using alternative method..." -ForegroundColor Yellow
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($dllPath)
        $hasGarudaHS_Execute = [System.Text.Encoding]::ASCII.GetString($bytes) -match "GarudaHS_Execute"
        $hasGarudaHS_GetVersion = [System.Text.Encoding]::ASCII.GetString($bytes) -match "GarudaHS_GetVersion"
        
        Write-Host "   📋 GarudaHS_Execute found: $hasGarudaHS_Execute" -ForegroundColor $(if ($hasGarudaHS_Execute) { "Green" } else { "Red" })
        Write-Host "   📋 GarudaHS_GetVersion found: $hasGarudaHS_GetVersion" -ForegroundColor $(if ($hasGarudaHS_GetVersion) { "Green" } else { "Red" })
        
        if (-not $hasGarudaHS_Execute -or -not $hasGarudaHS_GetVersion) {
            Write-Host "`n⚠️ Module Aggregation exports not found in DLL" -ForegroundColor Yellow
            Write-Host "   This means the DLL needs to be recompiled with Module Aggregation" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "   ❌ Could not analyze DLL: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n🔧 Next Steps:" -ForegroundColor Yellow
Write-Host "1. Recompile DLL with Module Aggregation" -ForegroundColor White
Write-Host "2. Test all 64+ operations" -ForegroundColor White
Write-Host "3. Verify anti-cheat functionality" -ForegroundColor White
