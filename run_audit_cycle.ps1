param(
    [string]$Sources = "f107,geomag_dst,geomag_kp,solar_wind,ndbc,coops_tide,usgs_stream",
    [int]$Limit = 1,
    [int]$MaxEvents = 7,
    [string]$GeometryPython = $env:GEOMETRY_PYTHON,
    [string]$MiddlewarePython = $env:MIDDLEWARE_PYTHON,
    [string]$GeometryScript = $env:GEOMETRY_SCRIPT,
    [string]$MiddlewareRoot = $PSScriptRoot
)

$env:PYTHONUTF8 = "1"

if (-not $GeometryPython -or -not $MiddlewarePython -or -not $GeometryScript) {
    throw "Set GEOMETRY_PYTHON, MIDDLEWARE_PYTHON, and GEOMETRY_SCRIPT before running."
}

$health = Invoke-RestMethod -Uri "http://127.0.0.1:5002/health" -TimeoutSec 10
if ($health.status -ne "healthy") {
    throw "Geometry API is not healthy: $($health.status)"
}

$null = Invoke-RestMethod -Uri "http://127.0.0.1:5005/brain/stats" -TimeoutSec 10

& $GeometryPython $GeometryScript --sources $Sources --limit $Limit
if ($LASTEXITCODE -ne 0) {
    throw "Ingestion failed with exit code $LASTEXITCODE"
}

Push-Location $MiddlewareRoot
try {
    & $MiddlewarePython main.py --max-events $MaxEvents
    if ($LASTEXITCODE -ne 0) {
        throw "Audit failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
