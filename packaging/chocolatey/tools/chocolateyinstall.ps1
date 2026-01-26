$ErrorActionPreference = "Stop"

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
    throw "Python 3.11+ is required. Please install Python and retry."
}

if ($pythonExe -like "*\\py.exe") {
    & $pythonExe -3 -m pip install --upgrade pip
    & $pythonExe -3 -m pip install --upgrade terraform-guardrail
} else {
    & $pythonExe -m pip install --upgrade pip
    & $pythonExe -m pip install --upgrade terraform-guardrail
}
