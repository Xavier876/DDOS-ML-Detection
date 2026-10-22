r"""Folder locations, independent of the current working directory.

    <solution>\                      DDOS-ML-Detection.sln
        data\                        datasets (git-ignored)
        DDoSDetector\                this project: app\, train\, models\, logs\ ...

In a PyInstaller build, models\ and logs\ sit next to the .exe.
"""
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    PROJECT_DIR = Path(sys.executable).resolve().parent
else:
    PROJECT_DIR = Path(__file__).resolve().parents[1]
SOLUTION_DIR = PROJECT_DIR.parent

APP_DATA_DIR = Path(__file__).resolve().parent / "data"   # feature_notes.json, feature_evidence.csv
FEATURE_NOTES = APP_DATA_DIR / "feature_notes.json"
FEATURE_EVIDENCE = APP_DATA_DIR / "feature_evidence.csv"   # written by notebook section 9b

MODELS_DIR = PROJECT_DIR / "models"
LOG_DIR = PROJECT_DIR / "logs"
DATA_DIR = SOLUTION_DIR / "data"
