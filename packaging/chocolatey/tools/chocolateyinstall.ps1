$ErrorActionPreference = "Stop"

if (Get-Command refreshenv -ErrorAction SilentlyContinue) {
    refreshenv
}
if (Get-Command Update-SessionEnvironment -ErrorAction SilentlyContinue) {
    Update-SessionEnvironment
}

$env:PIP_DISABLE_PIP_VERSION_CHECK = "1"
$env:PIP_NO_INPUT = "1"

function Get-PythonExecutable {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return $python.Path
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return $py.Path
    }
    return $null
}

$pythonExe = Get-PythonExecutable
if (-not $pythonExe) {
    $candidates = @(
        "C:\\Python311\\python.exe",
        "C:\\Python312\\python.exe",
        "C:\\Python313\\python.exe",
        "C:\\Python314\\python.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            $pythonExe = $candidate
            break
        }
    }
}

if (-not $pythonExe) {
    throw "Python 3.11+ is required but not found on PATH. Ensure the python dependency is installed."
}

if ($pythonExe -like "*\\py.exe") {
    & $pythonExe -3 -m pip --version
    if ($LASTEXITCODE -ne 0) {
        & $pythonExe -3 -m ensurepip --upgrade
    }
    & $pythonExe -3 -m pip install --upgrade --no-input terraform-guardrail
} else {
    & $pythonExe -m pip --version
    if ($LASTEXITCODE -ne 0) {
        & $pythonExe -m ensurepip --upgrade
    }
    & $pythonExe -m pip install --upgrade --no-input terraform-guardrail
}
