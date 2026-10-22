"""Entry point: python -m app.main [flows.csv]"""
from __future__ import annotations

import logging
import sys
import traceback
from pathlib import Path

if not __package__:  # run as a script (e.g. Visual Studio "Set as Startup Item"): make `app` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import matplotlib

matplotlib.use("QtAgg")  # must happen before anything imports pyplot

from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from app.paths import LOG_DIR, MODELS_DIR  # noqa: E402


def setup_logging() -> Path:
    LOG_DIR.mkdir(exist_ok=True)
    log_file = LOG_DIR / "app.log"
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=[logging.FileHandler(log_file, encoding="utf-8"), logging.StreamHandler()])
    return log_file


def install_excepthook():
    """Show unexpected errors in a dialog and keep the app running."""
    def hook(exc_type, exc, tb):
        logging.getLogger("app").error("unhandled error", exc_info=(exc_type, exc, tb))
        if QApplication.instance():
            QMessageBox.critical(None, "Unexpected error",
                                 f"{exc_type.__name__}: {exc}\n\nThe app will keep running. "
                                 "Details are in logs/app.log.\n\n" + "".join(traceback.format_tb(tb))[-1500:])
    sys.excepthook = hook


def main(argv=None) -> int:
    argv = sys.argv if argv is None else argv
    setup_logging()
    install_excepthook()
    app = QApplication(argv)
    app.setApplicationName("Explainable DDoS detection")
    from app.ui.main_window import MainWindow   # after QApplication exists

    win = MainWindow(MODELS_DIR)
    win.show()
    if len(argv) > 1 and Path(argv[1]).is_file():
        win.open_csv(Path(argv[1]))
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
