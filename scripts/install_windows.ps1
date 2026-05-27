# Dragon Legion — Windows Setup Script
# Installs Python dependencies for master node operation.
# Hardware modules require Linux workers.
#
# Run as: powershell -ExecutionPolicy Bypass -File install_windows.ps1

$ErrorActionPreference = "Stop"

Write-Host "  ⚔  Dragon Legion — Windows Setup" -ForegroundColor Cyan
Write-Host "  The Legion kneels to no key." -ForegroundColor Cyan
Write-Host ""

# Check for Python
Write-Host "[*] Checking Python installation..." -ForegroundColor Green
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  Found: $pythonVersion"
} catch {
    Write-Host "[!] Python 3.10+ not found. Download from https://python.org" -ForegroundColor Red
    exit 1
}

# Install Python packages
Write-Host "[*] Installing Python packages..." -ForegroundColor Green
Set-Location (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
pip install --upgrade pip
pip install -r requirements.txt

Write-Host ""
Write-Host "[*] Note: Windows runs master node only." -ForegroundColor Yellow
Write-Host "  Hardware modules (USB attacks, SDR, NFC) require Linux workers."
Write-Host "  Use WSL2 or a Linux VM for worker functionality."
Write-Host ""

# Check for WSL
$wsl = wsl --status 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[*] WSL detected. You can run workers under WSL." -ForegroundColor Green
    Write-Host "  Run: wsl sudo bash scripts/install_linux.sh"
} else {
    Write-Host "[*] WSL not detected. Install for full worker support:" -ForegroundColor Yellow
    Write-Host "  wsl --install"
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Dragon Legion setup complete." -ForegroundColor Green
Write-Host "  Start master: python -m dragon_legion.main master" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Cyan
