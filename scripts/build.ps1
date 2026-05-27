# CellLink Build Script (Windows PowerShell)
# Builds the Android APK with NDK native code

param(
    [string]$BuildType = "debug",
    [string]$AbiFilter = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CellLink — Direct Cellular Link Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for Android SDK
$sdkPath = $env:ANDROID_SDK_ROOT
if (-not $sdkPath) {
    $sdkPath = $env:ANDROID_HOME
}
if (-not $sdkPath) {
    # Common Windows paths
    $commonPaths = @(
        "$env:LOCALAPPDATA\Android\Sdk",
        "C:\Android\Sdk",
        "$env:APPDATA\Android\Sdk"
    )
    foreach ($p in $commonPaths) {
        if (Test-Path $p) {
            $sdkPath = $p
            break
        }
    }
}
if (-not $sdkPath) {
    Write-Error "Android SDK not found. Set ANDROID_SDK_ROOT or ANDROID_HOME."
    exit 1
}
Write-Host "[OK] Android SDK: $sdkPath" -ForegroundColor Green

# Check for NDK
$ndkPath = "$sdkPath\ndk"
if (-not (Test-Path $ndkPath)) {
    Write-Error "Android NDK not found at $ndkPath. Install via SDK Manager."
    exit 1
}
$ndkVersions = Get-ChildItem $ndkPath -Directory | Sort-Object Name -Descending
if ($ndkVersions.Count -eq 0) {
    Write-Error "No NDK version found. Install via SDK Manager."
    exit 1
}
$ndkVersion = $ndkVersions[0].Name
Write-Host "[OK] Android NDK: $ndkVersion" -ForegroundColor Green

# Set NDK environment
$env:ANDROID_NDK_HOME = "$ndkPath\$ndkVersion"

# Build command
$gradleArgs = @(
    "assemble${BuildType}"
)

if ($AbiFilter) {
    Write-Host "[INFO] Building for ABI: $AbiFilter" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Building CellLink ($BuildType)..." -ForegroundColor Yellow

Push-Location $ProjectRoot
try {
    if (Test-Path ".\gradlew.bat") {
        & .\gradlew.bat @gradleArgs
    } else {
        & gradle @gradleArgs
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "[OK] Build complete!" -ForegroundColor Green

# Find the APK
$apkPath = Get-ChildItem -Path "$ProjectRoot\app\build\outputs\apk" -Recurse -Filter "*.apk" |
    Where-Object { $_.Name -like "*$BuildType*" } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($apkPath) {
    $sizeMB = [math]::Round($apkPath.Length / 1MB, 2)
    Write-Host "APK: $($apkPath.FullName) ($sizeMB MB)" -ForegroundColor Green
} else {
    Write-Host "APK not found in expected location. Check build output." -ForegroundColor Yellow
}
