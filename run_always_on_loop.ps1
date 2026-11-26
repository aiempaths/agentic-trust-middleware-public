$ErrorActionPreference = "Continue"
$watchdog = Join-Path $PSScriptRoot "keep_system_alive.ps1"
$log = Join-Path $PSScriptRoot "keep_system_alive.log"
$intervalSeconds = 300

$configured = $env:AUDIT_LOOP_SECONDS
if ($configured -match '^\d+$' -and [int]$configured -gt 0) {
    $intervalSeconds = [int]$configured
}

while ($true) {
    try {
        & $watchdog
    }
    catch {
        Add-Content -LiteralPath $log -Value ("{0} LOOP ERROR: {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_.Exception.Message) -Encoding UTF8
    }
    Start-Sleep -Seconds $intervalSeconds
}
