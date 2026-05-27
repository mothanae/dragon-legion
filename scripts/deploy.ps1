# CellLink Deploy Script (Windows PowerShell)
# Installs the APK on a connected Android device via ADB

param(
    [switch]$UninstallFirst,
    [switch]$GrantPermissions
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CellLink — Deploy to Device" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check ADB
$adb = Get-Command adb -ErrorAction SilentlyContinue
if (-not $adb) {
    Write-Error "ADB not found in PATH. Install Android Platform Tools."
    exit 1
}

# Check for connected device
$devices = & adb devices | Select-String -Pattern "device$"
if ($devices.Count -eq 0) {
    Write-Error "No Android device connected. Connect via USB and enable USB debugging."
    exit 1
}
Write-Host "[OK] Device connected" -ForegroundColor Green

# Check for root (required for DIAG port)
$hasRoot = & adb shell "su -c 'echo root_ok'" 2>$null
if ($hasRoot -match "root_ok") {
    Write-Host "[OK] Root access available" -ForegroundColor Green
} else {
    Write-Host "[WARN] Root access not detected. DIAG port may be inaccessible." -ForegroundColor Yellow
    Write-Host "       The app requires a rooted device with dm-verity disabled."
}

# Find the APK
$apkFiles = Get-ChildItem -Path "$ProjectRoot\app\build\outputs\apk" -Recurse -Filter "*.apk" |
    Where-Object { $_.Name -notlike "*unaligned*" -and $_.Name -notlike "*unsigned*" } |
    Sort-Object LastWriteTime -Descending

if ($apkFiles.Count -eq 0) {
    Write-Error "No APK found. Run build.ps1 first."
    exit 1
}

$apk = $apkFiles[0]
Write-Host "APK: $($apk.Name) ($([math]::Round($apk.Length / 1MB, 2)) MB)" -ForegroundColor Green

# Uninstall if requested
if ($UninstallFirst) {
    Write-Host "Uninstalling existing app..." -ForegroundColor Yellow
    & adb uninstall com.celllink 2>$null
    Write-Host "[OK] Uninstalled" -ForegroundColor Green
}

# Install
Write-Host "Installing..." -ForegroundColor Yellow
$installResult = & adb install -r $apk.FullName 2>&1
if ($LASTEXITCODE -ne 0 -or $installResult -notmatch "Success") {
    Write-Error "Install failed: $installResult"
    exit 1
}
Write-Host "[OK] Installed" -ForegroundColor Green

# Grant permissions
if ($GrantPermissions) {
    Write-Host "Granting permissions..." -ForegroundColor Yellow
    $permissions = @(
        "android.permission.MODIFY_PHONE_STATE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PRECISE_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.RECORD_AUDIO",
        "android.permission.MODIFY_AUDIO_SETTINGS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    )
    foreach ($perm in $permissions) {
        & adb shell pm grant com.celllink $perm 2>$null
    }
    Write-Host "[OK] Permissions granted" -ForegroundColor Green
}

# Reminder about DIAG port
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  REMINDER: DIAG Port Setup" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "1. On Phone A (Tower), open the Phone app"
Write-Host "   and dial: *#0808#"
Write-Host "2. Select 'DM + MODEM + ADB' or 'DIAG + ADB'"
Write-Host "3. Reboot the phone"
Write-Host "4. Verify DIAG port: adb shell ls /dev/diag"
Write-Host ""
Write-Host "To launch the app:"
Write-Host "  adb shell am start -n com.celllink/.MainActivity"
Write-Host ""
