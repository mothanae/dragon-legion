# CellLink DIAG Port Setup Helper
# Helps verify and configure the Qualcomm DIAG port on a connected device
# Run after connecting a rooted Qualcomm device via USB

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CellLink — DIAG Port Diagnostic Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$adb = Get-Command adb -ErrorAction SilentlyContinue
if (-not $adb) {
    Write-Error "ADB not found in PATH."
    exit 1
}

# Check device connection
Write-Host "[1] Checking device connection..." -ForegroundColor Yellow
$deviceInfo = & adb shell getprop ro.product.manufacturer 2>$null
$deviceModel = & adb shell getprop ro.product.model 2>$null
if (-not $deviceInfo) {
    Write-Error "No device detected. Connect via USB with debugging enabled."
    exit 1
}
Write-Host "  Device: $deviceInfo $deviceModel" -ForegroundColor Green

# Check SoC
Write-Host "[2] Checking SoC..." -ForegroundColor Yellow
$soc = & adb shell getprop ro.board.platform 2>$null
$hardware = & adb shell getprop ro.hardware 2>$null
Write-Host "  Platform: $soc" -ForegroundColor Cyan
Write-Host "  Hardware: $hardware" -ForegroundColor Cyan

if ($soc -match "msm" -or $soc -match "sdm" -or $hardware -match "qcom") {
    Write-Host "  [OK] Qualcomm SoC detected" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Non-Qualcomm SoC detected. DIAG may use different paths." -ForegroundColor Yellow
}

# Check root
Write-Host "[3] Checking root..." -ForegroundColor Yellow
$rootCheck = & adb shell "su -c 'id -u'" 2>$null
if ($rootCheck -match "0") {
    Write-Host "  [OK] Root access available (UID 0)" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Root access not available" -ForegroundColor Yellow
}

# Check DIAG device
Write-Host "[4] Checking DIAG device files..." -ForegroundColor Yellow
$diagPaths = @(
    "/dev/diag",
    "/dev/ttyUSB0",
    "/dev/ttyUSB1",
    "/dev/ttyUSB2",
    "/dev/ttyACM0",
    "/dev/smd0",
    "/dev/smd7",
    "/dev/smd11"
)

$foundDiag = $false
foreach ($path in $diagPaths) {
    $exists = & adb shell "su -c 'test -e $path && echo EXISTS'" 2>$null
    if ($exists -match "EXISTS") {
        $perms = & adb shell "su -c 'ls -la $path'" 2>$null
        Write-Host "  [OK] $path — $perms" -ForegroundColor Green
        $foundDiag = $true
    }
}

if (-not $foundDiag) {
    Write-Host "  [FAIL] No DIAG device files found" -ForegroundColor Red
    Write-Host ""
    Write-Host "  === DIAG PORT ENABLE INSTRUCTIONS ===" -ForegroundColor Yellow
    Write-Host "  1. Open the Phone dialer app"
    Write-Host "  2. Dial: *#0808#"
    Write-Host "  3. Select 'DM + MODEM + ADB' or 'DIAG + ADB'"
    Write-Host "  4. Tap OK and reboot the phone"
    Write-Host "  5. Reconnect USB and run this script again"
    Write-Host ""
    Write-Host "  Note: On some devices, the code might be:"
    Write-Host "    - *#*#8778#*#* (Samsung)"
    Write-Host "    - *#*#3646633#*#* (MediaTek engineering mode)"
}

# Check SELinux
Write-Host "[5] Checking SELinux status..." -ForegroundColor Yellow
$selinux = & adb shell "su -c 'getenforce'" 2>$null
Write-Host "  SELinux: $selinux" -ForegroundColor Cyan
if ($selinux -match "Enforcing") {
    Write-Host "  [WARN] SELinux is enforcing. May block DIAG access." -ForegroundColor Yellow
    Write-Host "  Run: adb shell su -c 'setenforce 0' to set permissive (temporary)"
}

# Check modem firmware version
Write-Host "[6] Checking modem firmware..." -ForegroundColor Yellow
$modemVersion = & adb shell "su -c 'cat /sys/devices/soc0/build_id'" 2>$null
if (-not $modemVersion) {
    $modemVersion = & adb shell getprop ro.bootimage.build.fingerprint 2>$null
}
Write-Host "  Build: $modemVersion" -ForegroundColor Cyan

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
if ($foundDiag) {
    Write-Host "  DIAG port is ready! You can build and deploy CellLink." -ForegroundColor Green
} else {
    Write-Host "  DIAG port not found. Follow the instructions above." -ForegroundColor Yellow
    Write-Host "  After enabling, run: build.ps1 && deploy.ps1" -ForegroundColor Yellow
}
Write-Host "========================================" -ForegroundColor Cyan
