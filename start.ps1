# BruteShield — One-Click Startup (Windows PowerShell)
# Run this from the project root: .\start.ps1

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$backendDir  = Join-Path $projectRoot 'backend'
$venvDir     = Join-Path $projectRoot 'venv'
$reqFile     = Join-Path $backendDir  'requirements.txt'

Write-Host ""
Write-Host "  =================================" -ForegroundColor Cyan
Write-Host "   BruteShield — Log Analyzer v1.0" -ForegroundColor Cyan
Write-Host "  =================================" -ForegroundColor Cyan
Write-Host ""

# ── Create virtual environment if needed ─────────────────────────────────────
if (-not (Test-Path $venvDir)) {
    Write-Host "  [1/3] Creating virtual environment..." -ForegroundColor Yellow
    python -m venv $venvDir
} else {
    Write-Host "  [1/3] Virtual environment found." -ForegroundColor Green
}

# ── Activate venv ─────────────────────────────────────────────────────────────
$activateScript = Join-Path $venvDir 'Scripts\Activate.ps1'
if (Test-Path $activateScript) {
    & $activateScript
} else {
    Write-Host "  Could not find venv activate script. Using system Python." -ForegroundColor Yellow
}

# ── Install requirements ──────────────────────────────────────────────────────
Write-Host "  [2/3] Installing Python dependencies..." -ForegroundColor Yellow
pip install -q -r $reqFile
Write-Host "  [2/3] Dependencies ready." -ForegroundColor Green

# ── Start Flask server ────────────────────────────────────────────────────────
Write-Host "  [3/3] Starting Flask API on http://localhost:5000 ..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  → Open  frontend\index.html  in your browser" -ForegroundColor Magenta
Write-Host "  → Press Ctrl+C to stop the server"            -ForegroundColor Gray
Write-Host ""

Set-Location $backendDir
python server.py
