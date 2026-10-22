"""Background workers. Heavy work (reading, scoring, SHAP) never runs on the UI thread.

A Worker wraps a plain function fn(progress, cancelled) -> result and reports back through
Qt signals, which are delivered on the UI thread. Workers never touch widgets.
"""
from __future__ import annotations

import logging
import threading
import traceback

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal

from app.core.csv_reader import Cancelled

log = logging.getLogger(__name__)


class WorkerSignals(QObject):
    progress = Signal(float)        # 0..1
    result = Signal(object)
    error = Signal(object, str)     # exception, traceback text
    cancelled = Signal()
    finished = Signal()


class Worker(QRunnable):
    def __init__(self, fn, name: str = "job"):
        super().__init__()
        self.fn, self.name = fn, name
        self.signals = WorkerSignals()
        self._cancel = threading.Event()
        self.setAutoDelete(False)   # we keep a reference until finished

    def cancel(self):
        self._cancel.set()

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def run(self):
        try:
            out = self.fn(self.signals.progress.emit, self.is_cancelled)
            if self.is_cancelled():
                self.signals.cancelled.emit()
            else:
                self.signals.result.emit(out)
        except Cancelled:
            self.signals.cancelled.emit()
        except Exception as e:  # report every failure to the UI instead of crashing
            log.exception("worker %s failed", self.name)
            self.signals.error.emit(e, traceback.format_exc())
        finally:
            self.signals.finished.emit()


class Jobs:
    """Starts workers and keeps them alive until they finish."""

    def __init__(self):
        self.pool = QThreadPool.globalInstance()
        self._running: set[Worker] = set()

    def start(self, fn, name="job", on_result=None, on_error=None, on_progress=None,
              on_cancelled=None, on_finished=None) -> Worker:
        w = Worker(fn, name)
        s = w.signals
        # Queued: callbacks run on the thread that owns `s` (the UI thread), never the worker.
        q = Qt.ConnectionType.QueuedConnection
        for sig, cb in ((s.result, on_result), (s.error, on_error), (s.progress, on_progress),
                        (s.cancelled, on_cancelled), (s.finished, on_finished)):
            if cb:
                sig.connect(cb, q)
        s.finished.connect(lambda: self._running.discard(w), q)
        self._running.add(w)
        self.pool.start(w)
        return w

    def wait(self, msecs: int = -1) -> bool:
        return self.pool.waitForDone(msecs)
