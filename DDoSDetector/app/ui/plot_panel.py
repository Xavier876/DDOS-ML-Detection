"""Tabbed chart area: one tab per registered ChartPlugin.

Only the visible tab is drawn. Heavy work (plugin.prepare, i.e. SHAP) runs in a worker;
drawing happens on the UI thread into a Figure owned by the tab (no pyplot figures).
"""
from __future__ import annotations

import logging
from pathlib import Path

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (QApplication, QComboBox, QDoubleSpinBox, QFileDialog, QHBoxLayout, QLabel,
                               QMessageBox, QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget)

from app.plots import _style as S
from app.plots.base import ChartContext, ChartPlugin, message, registry
from app.workers import Jobs

log = logging.getLogger(__name__)


class ChartTab(QWidget):
    def __init__(self, plugin: ChartPlugin, panel: "PlotPanel"):
        super().__init__()
        self.plugin, self.panel = plugin, panel
        self.figure = Figure(figsize=(7, 5), dpi=100)
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.status = QLabel("")
        self.status.setStyleSheet("color: #52514e;")
        save = QPushButton("Save as PNG…")
        copy = QPushButton("Copy to clipboard")
        save.clicked.connect(self.save_png)
        copy.clicked.connect(self.copy)
        bar = QHBoxLayout()
        bar.addWidget(self.status, 1)
        bar.addWidget(copy)
        bar.addWidget(save)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        self.option_boxes: dict[str, QWidget] = {}
        if plugin.options:     # the chart's own inputs (e.g. assumed prevalence, by column/group)
            row = QHBoxLayout()
            for key, opt in plugin.options.items():
                if opt.choices:
                    sb = QComboBox()
                    sb.addItems(list(opt.choices))
                    sb.setCurrentIndex(int(opt.default))
                    sb.currentIndexChanged.connect(lambda v, k=key: self.panel.option_changed(self, k, v))
                else:
                    sb = QDoubleSpinBox()
                    sb.setRange(opt.minimum, opt.maximum)
                    sb.setDecimals(opt.decimals)
                    sb.setSingleStep(opt.step)
                    sb.setValue(opt.default)
                    sb.setSuffix(opt.suffix)
                    sb.valueChanged.connect(lambda v, k=key: self.panel.option_changed(self, k, v))
                row.addWidget(QLabel(opt.label + ":"))
                row.addWidget(sb)
                self.option_boxes[key] = sb
            row.addStretch(1)
            lay.addLayout(row)
        lay.addWidget(self.canvas, 1)
        lay.addLayout(bar)
        self.dirty = True
        self.generation = 0

    def show_message(self, text: str):
        self.figure.clear()
        S.style_figure(self.figure)
        message(self.figure, text)
        self.canvas.draw_idle()

    def draw(self, ctx: ChartContext):
        self.figure.clear()
        try:
            self.plugin.render(self.figure, ctx)
        except Exception as e:  # a broken chart must not take the app down
            log.exception("chart %s failed", self.plugin.name)
            self.figure.clear()
            message(self.figure, f"Could not draw this chart:\n{e}")
        self.canvas.draw_idle()

    def default_name(self) -> str:
        return "".join(ch if ch.isalnum() else "_" for ch in self.plugin.name).strip("_").lower() + ".png"

    def save_png(self, path: str | None = None):
        if not path:
            start = str(Path(self.panel.last_dir) / self.default_name())
            path, _ = QFileDialog.getSaveFileName(self, "Save chart as PNG", start, "PNG image (*.png)")
            if not path:
                return
        try:
            self.figure.savefig(path, dpi=150, facecolor=self.figure.get_facecolor())
            self.panel.last_dir = str(Path(path).parent)
            self.status.setText(f"Saved {Path(path).name}")
        except Exception as e:
            QMessageBox.warning(self, "Save failed", f"Could not save the chart:\n{e}")

    def copy(self):
        QApplication.clipboard().setPixmap(self.canvas.grab())
        self.status.setText("Copied to clipboard")


class PlotPanel(QWidget):
    busy = Signal(str)          # message for the status bar ("" = idle)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.jobs = Jobs()
        self.ctx: ChartContext | None = None
        self.files: dict = {}          # extra result files opened by the user (e.g. comparison CSV)
        self.last_dir = str(Path.cwd())
        self.tabs = QTabWidget()
        self.chart_tabs: list[ChartTab] = []
        for cls in registry():
            tab = ChartTab(cls(), self)
            self.chart_tabs.append(tab)
            self.tabs.addTab(tab, cls.name)
        self.tabs.currentChanged.connect(lambda _: self.refresh_current())

        self.sample = QSpinBox()
        self.sample.setRange(100, 20_000)
        self.sample.setSingleStep(500)
        self.sample.setValue(2000)
        self.sample.setToolTip("Rows sampled for global SHAP charts (more = slower, steadier)")
        self.sample.valueChanged.connect(self._sample_changed)
        top = QHBoxLayout()
        top.addWidget(QLabel("Global SHAP sample:"))
        top.addWidget(self.sample)
        top.addWidget(QLabel("flows"))
        top.addStretch(1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(top)
        lay.addWidget(self.tabs, 1)

        self._redraw_timer = QTimer(self, singleShot=True, interval=120)
        self._redraw_timer.timeout.connect(self.refresh_current)
        for t in self.chart_tabs:
            t.show_message("Open a flows CSV to see charts.")

    # --- context updates from the main window -------------------------------------------
    def set_context(self, ctx: ChartContext | None):
        self.ctx = ctx
        if ctx is not None:
            ctx.sample_size = self.sample.value()
            for t in self.chart_tabs:          # keep the user's option values across reloads
                for key, sb in t.option_boxes.items():
                    ctx.options[t.plugin.option_key(key)] = (sb.currentIndex() if isinstance(sb, QComboBox)
                                                             else sb.value())
            ctx.files.update(self.files)
        for i, t in enumerate(self.chart_tabs):
            ok = ctx is None or not t.plugin.needs_label or ctx.has_label
            self.tabs.setTabEnabled(i, ok)
            self.tabs.setTabToolTip(i, "" if ok else "Needs a Label column in the loaded CSV")
            if not ok and self.tabs.currentIndex() == i:
                self.tabs.setCurrentIndex(0)
        self.mark_dirty()
        if ctx is None:
            for t in self.chart_tabs:
                t.show_message("Open a flows CSV to see charts.")
        self.refresh_current()

    def mark_dirty(self, scope: str | None = None):
        for t in self.chart_tabs:
            if scope is None or t.plugin.scope == scope:
                t.dirty = True

    def select_row(self, pos: int | None, show: bool = True):
        if self.ctx is None:
            return
        self.ctx.selected = pos
        self.mark_dirty("row")
        if show and pos is not None:
            for i, t in enumerate(self.chart_tabs):
                if t.plugin.scope == "row":
                    if self.tabs.currentIndex() != i:
                        self.tabs.setCurrentIndex(i)   # triggers refresh_current
                        return
                    break
        self.refresh_current()

    def set_threshold(self, t: float):
        if self.ctx is None:
            return
        self.ctx.threshold = t
        self.mark_dirty()          # titles / threshold lines change; SHAP stays cached
        self._redraw_timer.start()

    def set_file(self, kind: str, path):
        """Give charts a result file the user opened (File -> Open comparison results...)."""
        self.files[kind] = path
        if self.ctx is not None:
            self.ctx.files[kind] = path
            self.mark_dirty()
            self.refresh_current()

    def option_changed(self, tab: ChartTab, key: str, value: float):
        if self.ctx is None:
            return
        self.ctx.options[tab.plugin.option_key(key)] = value
        tab.dirty = True
        self._redraw_timer.start()

    def _sample_changed(self, n: int):
        if self.ctx is None:
            return
        self.ctx.sample_size = n
        self.mark_dirty("global")
        self._redraw_timer.start()

    # --- drawing -------------------------------------------------------------------------
    def current_tab(self) -> ChartTab | None:
        w = self.tabs.currentWidget()
        return w if isinstance(w, ChartTab) else None

    def refresh_current(self):
        tab = self.current_tab()
        if tab is None or self.ctx is None or not tab.dirty:
            return
        self.render_tab(tab)

    def render_tab(self, tab: ChartTab, on_done=None):
        ctx = self.ctx
        tab.dirty = False
        tab.generation += 1
        gen = tab.generation
        tab.status.setText("Computing…")
        self.busy.emit(f"Computing '{tab.plugin.name}'…")

        def work(progress, cancelled):
            tab.plugin.prepare(ctx)

        def done(_):
            if gen != tab.generation or ctx is not self.ctx:
                return            # a newer request replaced this one
            tab.draw(ctx)
            tab.status.setText("")
            self.busy.emit("")
            if on_done:
                on_done()

        def failed(e, tb):
            tab.status.setText("")
            self.busy.emit("")
            tab.show_message(f"Could not compute this chart:\n{e}")

        self.jobs.start(work, name=tab.plugin.name, on_result=done, on_error=failed)
