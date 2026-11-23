# Run AIMsquare on this computer.
# Start it with:  powershell -ExecutionPolicy Bypass -File .\run-local.ps1
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "First run: creating the Python environment..."
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Python was not found. Install it from python.org (tick 'Add python.exe to PATH'), reopen VS Code and try again."
        exit 1
    }
}
$py = ".venv\Scripts\python.exe"

if (-not (Test-Path ".venv\.installed")) {
    Write-Host "Installing packages (one time, about a minute)..."
    & $py -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Package install failed. Copy the error above and send it to Claude."
        exit 1
    }
    New-Item ".venv\.installed" -ItemType File | Out-Null
}

# Local-only settings. The database sits in your temp folder so OneDrive does not sync it.
$env:AIM_SECRET = "local-testing-secret-0123456789abcdef-not-for-hosting"
$env:AIM_DB = Join-Path $env:TEMP "aim.db"

# The API key is asked for here and kept only for this run. It is never written to a file.
$secure = Read-Host "Anthropic API key (press Enter to skip; the Assistant stays off)" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
if ($plain) { $env:ANTHROPIC_API_KEY = $plain }

# Support is off by default: the Support panel just says it is yet to be configured.
# Type y to switch it on later. With no agent ID it answers from a built-in guide (needs the API key).
$on = Read-Host "Switch Support on? (y/N)"
if ($on -match "^[yY]") {
    $env:AIM_SUPPORT_ENABLED = "1"
    $a = Read-Host "Support agent ID (press Enter to use the built-in guide instead)"
    if ($a) {
        $env:AIM_SUPPORT_AGENT_ID = $a.Trim()
        $e = Read-Host "Support environment ID, e.g. env_01... (from tools\create_support_environment.py)"
        if ($e) { $env:AIM_SUPPORT_ENV_ID = $e.Trim() }
        $v = Read-Host "Vault ID(s) for Notion and Slack, comma-separated (press Enter to skip)"
        if ($v) { $env:AIM_SUPPORT_VAULT_IDS = $v.Trim() }
    }
}

Write-Host ""
Write-Host "Open http://localhost:8000 in your browser. Press Ctrl+C here to stop."
Write-Host ""
& $py -m uvicorn app:app --port 8000
