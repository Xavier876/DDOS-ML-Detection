# Package the app as a one-folder Windows program with PyInstaller.
#   powershell -ExecutionPolicy Bypass -File DDoSDetector\build_exe.ps1
# Output: DDoSDetector\bin\Release\DDoSExplainer\DDoSExplainer.exe (+ models\). Intermediates: obj\.
$ErrorActionPreference = "Stop"
$proj = $PSScriptRoot
$py = Join-Path (Split-Path $proj -Parent) ".venv\Scripts\python.exe"
$out = Join-Path $proj "bin\Release"

& $py -m pip install -q pyinstaller
Push-Location $proj
try {
    # --collect-all xgboost fails (it imports xgboost.testing), so collect data/binaries only.
    # --collect-submodules app: chart plugins are discovered at runtime, PyInstaller can't see them.
    # --add-data needs an absolute source: PyInstaller resolves it relative to --specpath.
    & $py -m PyInstaller --noconfirm --windowed --name DDoSExplainer --paths . `
        --collect-submodules app --add-data "$proj\app\data;app\data" `
        --collect-data xgboost --collect-binaries xgboost --collect-data shap --collect-binaries shap `
        --exclude-module xgboost.testing --exclude-module PySide6.QtWebEngineCore --exclude-module pytest `
        --workpath obj\pyinstaller --specpath obj\pyinstaller --distpath $out app\main.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit $LASTEXITCODE)" }
    Copy-Item -Recurse -Force models (Join-Path $out "DDoSExplainer\models")
    Write-Host "Built $out\DDoSExplainer\DDoSExplainer.exe"
}
finally {
    Pop-Location
}
