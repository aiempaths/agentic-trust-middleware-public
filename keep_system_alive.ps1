param(
    [string]$VaultRoot = $env:VAULT_ROOT,
    [string]$GeometryRoot = $env:GEOMETRY_ROOT,
    [string]$BrainRoot = $env:BRAIN_ROOT,
    [string]$Python = $env:PYTHON_EXE,
    [string]$GeometryPython = $env:GEOMETRY_PYTHON,
    [string]$OllamaApp = $env:OLLAMA_APP,
    [string]$OllamaServer = $env:OLLAMA_SERVER
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:USE_WAITRESS = "1"
$env:BRAIN_HOST = "127.0.0.1"
$env:BRAIN_PORT = "5005"

if (-not $VaultRoot -or -not $GeometryRoot -or -not $BrainRoot -or -not $Python -or -not $GeometryPython) {
    throw "Set VAULT_ROOT, GEOMETRY_ROOT, BRAIN_ROOT, PYTHON_EXE, and GEOMETRY_PYTHON before running."
}

$Log = Join-Path $PSScriptRoot "keep_system_alive.log"
$Lock = Join-Path $PSScriptRoot "keep_system_alive.lock"

function Write-Log {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $Log -Value $line -Encoding UTF8
}

function Test-Port {
    param([int]$Port)
    $connections = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    return $connections.Count -gt 0
}

function Wait-Port {
    param([int]$Port, [int]$Attempts = 30)
    for ($i = 0; $i -lt $Attempts; $i++) {
        if (Test-Port -Port $Port) {
            return $true
        }
        Start-Sleep -Seconds 2
    }
    return Test-Port -Port $Port
}

function Test-ProcessCommandLine {
    param([string]$Needle)
    $processes = @(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Needle) })
    return $processes.Count -gt 0
}

function Stop-ProcessesByNeedle {
    param([string]$Needle)
    $processes = @(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Needle) })
    foreach ($process in $processes) {
        try {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
            Write-Log "stopped stale process: $Needle pid=$($process.ProcessId)"
        }
        catch {
            Write-Log "could not stop process: $Needle pid=$($process.ProcessId) error=$($_.Exception.Message)"
        }
    }
}

function Start-App {
    param(
        [string]$Name,
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory
    )
    $outLog = Join-Path $PSScriptRoot ("{0}_out.log" -f $Name)
    $errLog = Join-Path $PSScriptRoot ("{0}_error.log" -f $Name)
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $outLog -RedirectStandardError $errLog -WindowStyle Hidden -PassThru
    Write-Log "started $Name pid=$($process.Id)"
}

function Test-Geometry {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:5002/health" -TimeoutSec 10
        return $health.status -eq "healthy"
    }
    catch {
        return $false
    }
}

function Test-Brain {
    try {
        $null = Invoke-RestMethod -Uri "http://127.0.0.1:5005/brain/stats" -TimeoutSec 10
        return $true
    }
    catch {
        return $false
    }
}

function Get-CollectorStatusAgeMinutes {
    $statusFile = Join-Path $VaultRoot "data\raw\collector_status.json"
    if (-not (Test-Path -LiteralPath $statusFile)) {
        return [double]::MaxValue
    }
    return ((Get-Date) - (Get-Item -LiteralPath $statusFile).LastWriteTime).TotalMinutes
}

if (Test-Path -LiteralPath $Lock) {
    $lockAge = (Get-Date) - (Get-Item -LiteralPath $Lock).LastWriteTime
    if ($lockAge.TotalMinutes -lt 15) {
        Write-Log "skip: another watchdog run is active"
        exit 0
    }
}

Set-Content -LiteralPath $Lock -Value ("pid={0} at={1}" -f $PID, (Get-Date -Format "o")) -Encoding UTF8

try {
    Write-Log "watchdog start"

    if (-not (Test-ProcessCommandLine -Needle "ollama app.exe")) {
        Start-App -Name ollama_app -FilePath $OllamaApp -Arguments @() -WorkingDirectory $VaultRoot
    }

    if (-not (Wait-Port -Port 11434 -Attempts 15)) {
        if (-not (Test-ProcessCommandLine -Needle "ollama.exe serve")) {
            Start-App -Name ollama_server -FilePath $OllamaServer -Arguments @("serve") -WorkingDirectory $VaultRoot
        }
        $null = Wait-Port -Port 11434 -Attempts 30
    }

    if (-not (Test-Port -Port 11434)) {
        throw "Ollama is not listening on port 11434"
    }

    if (-not (Test-Geometry)) {
        Stop-ProcessesByNeedle -Needle "geometry_api.py"
        Start-App -Name geometry -FilePath $GeometryPython -Arguments @("geometry_api.py") -WorkingDirectory $GeometryRoot
        $null = Wait-Port -Port 5002 -Attempts 45
    }

    if (-not (Test-Geometry)) {
        throw "Geometry API is not healthy on port 5002"
    }

    if (-not (Test-Brain)) {
        Stop-ProcessesByNeedle -Needle "-u app.py"
        Start-App -Name brain -FilePath $Python -Arguments @("-u", "app.py") -WorkingDirectory $BrainRoot
        $null = Wait-Port -Port 5005 -Attempts 30
    }

    if (-not (Test-Brain)) {
        throw "Brain is not healthy on port 5005"
    }

    if ((Get-CollectorStatusAgeMinutes) -gt 20) {
        Stop-ProcessesByNeedle -Needle "keep_collecting.py"
        Start-App -Name collector -FilePath $Python -Arguments @("-u", "keep_collecting.py") -WorkingDirectory $VaultRoot
        Start-Sleep -Seconds 5
    }

    if ((Get-CollectorStatusAgeMinutes) -gt 30) {
        Write-Log "warning: collector status is still stale"
    }

    & (Join-Path $PSScriptRoot "run_audit_cycle.ps1")
    if (-not $?) {
        throw "audit cycle reported failure"
    }

    Write-Log "watchdog complete"
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
finally {
    Remove-Item -LiteralPath $Lock -Force -ErrorAction SilentlyContinue
}
