"""Main window: results table (left) and chart panel (right) in a splitter."""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QAction, QActionGroup, QKeySequence
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QDoubleSpinBox, QFileDialog, QHBoxLayout,
                               QHeaderView, QInputDialog, QLabel, QMainWindow, QMenu, QMessageBox,
                               QProgressBar, QPushButton, QSlider, QSplitter, QTableView, QToolBar,
                               QVBoxLayout, QWidget)

from app.core import review as rv
from app.core.csv_reader import MissingColumnsError, read_flows, read_header
from app.core.explain import ExplainerCache, contributions, top_features
from app.core.features import (LABEL, TIME, TRACING_COLUMNS, extra_missing_mask, missing_columns, summary,
                               tools_from_labels)
from app.core.model_store import ModelBundle, list_models, load_bundle, model_columns, read_meta, read_metas
from app.core.scoring import (CODE_BENIGN, CODE_DDOS, CODE_NOT_SCORED, FLAG_NAMES, build_all, label_metrics,
                              score)
from app.plots.feature_set_comparison import FILE_KIND
from app.core.timing import RunTimings, Stopwatch
from app.paths import DATA_DIR
from app.plots.base import ChartContext
from app.ui.about_dialog import AboutDialog
from app.ui.features_dialog import FeaturesDialog
from app.ui.plot_panel import PlotPanel
from app.ui.results_table import ResultsData, ResultsTableModel
from app.workers import Jobs

log = logging.getLogger(__name__)
DEFAULT_MODELS = ("all_tools_f21", "all_tools_f15")   # first one found is loaded at start-up
VERDICT_SHORTCUTS = {rv.CONFIRMED: "Ctrl+1", rv.FALSE_POSITIVE: "Ctrl+2", rv.UNSURE: "Ctrl+3",
                     rv.UNREVIEWED: "Ctrl+0"}


class MainWindow(QMainWindow):
    def __init__(self, models_dir: Path):
        super().__init__()
        self.setWindowTitle("Explainable DDoS detection")
        self.resize(1500, 900)
        self.models_dir = Path(models_dir)
        self.settings = QSettings("COMP6310", "DDoSExplainer")
        self.jobs = Jobs()
        self.bundle: ModelBundle | None = None
        self.clean_df = None          # cleaned rows of the loaded CSV (kept for re-scoring)
        self.source_path: Path | None = None
        self.results: ResultsData | None = None
        self.timings = RunTimings()
        self.cache = ExplainerCache(on_timing=self.timings.record_shap)
        self._data_id = 0
        self._job = None
        self._n_extra_missing = 0

        self.table_model = ResultsTableModel(self)
        self._build_ui()
        self._build_menus()
        self._load_default_model()

    # =============================================================================== UI
    def _build_ui(self):
        # --- results side
        self.table = QTableView()
        self.table.setModel(self.table_model)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicatorShown(True)
        self.table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.horizontalHeader().setDefaultSectionSize(110)
        self.table.setAlternatingRowColors(True)
        self.table.selectionModel().currentRowChanged.connect(self._row_changed)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_menu)
        self.verdict_actions = {}
        for code, keys in VERDICT_SHORTCUTS.items():
            a = QAction(f"Verdict: {rv.VERDICTS[code]}", self.table, shortcut=QKeySequence(keys))
            a.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            a.triggered.connect(lambda _=False, c=code: self.set_verdict_selected(c))
            self.table.addAction(a)
            self.verdict_actions[code] = a
        self.note_action = QAction("Edit note…", self.table, shortcut=QKeySequence("Ctrl+N"))
        self.note_action.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.note_action.triggered.connect(self.edit_note_selected)
        self.table.addAction(self.note_action)

        # threshold
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(0, 1000)
        self.slider.setValue(500)
        self.thr = QDoubleSpinBox()
        self.thr.setRange(0.0, 1.0)
        self.thr.setDecimals(3)
        self.thr.setSingleStep(0.01)
        self.thr.setValue(0.5)
        self.thr.setToolTip("Flows with model score ≥ threshold are flagged DDoS (re-flags instantly, no re-scoring)")
        self.slider.valueChanged.connect(lambda v: self.thr.setValue(v / 1000))
        self.thr.valueChanged.connect(self._threshold_changed)

        # filters
        self.f_benign, self.f_ddos, self.f_ns = (QCheckBox("Benign"), QCheckBox("DDoS"), QCheckBox("Not scored"))
        for cb in (self.f_benign, self.f_ddos, self.f_ns):
            cb.setChecked(True)
            cb.toggled.connect(self._filters_changed)
        self.s_lo, self.s_hi = QDoubleSpinBox(), QDoubleSpinBox()
        for sb, v in ((self.s_lo, 0.0), (self.s_hi, 1.0)):
            sb.setRange(0.0, 1.0)
            sb.setDecimals(3)
            sb.setSingleStep(0.05)
            sb.setValue(v)
            sb.valueChanged.connect(self._filters_changed)
        uncertain = QPushButton("Uncertain (0.2–0.8)")
        uncertain.setToolTip("Show only flows with a middling model score")
        uncertain.clicked.connect(lambda: (self.s_lo.setValue(0.2), self.s_hi.setValue(0.8)))
        reset = QPushButton("Reset filters")
        reset.clicked.connect(self._reset_filters)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Threshold:"))
        row1.addWidget(self.slider, 1)
        row1.addWidget(self.thr)
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Show:"))
        for cb in (self.f_benign, self.f_ddos, self.f_ns):
            row2.addWidget(cb)
        row2.addSpacing(12)
        row2.addWidget(QLabel("Model score from"))
        row2.addWidget(self.s_lo)
        row2.addWidget(QLabel("to"))
        row2.addWidget(self.s_hi)
        row2.addWidget(uncertain)
        row2.addWidget(reset)
        row2.addStretch(1)

        self.summary = QLabel("No data loaded. File → Open flows CSV…")
        self.summary.setWordWrap(True)
        self.summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.summary.setStyleSheet("padding: 4px;")

        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(4, 4, 4, 4)
        lv.addLayout(row1)
        lv.addLayout(row2)
        lv.addWidget(self.table, 1)
        lv.addWidget(self.summary)

        # --- charts side
        self.plots = PlotPanel()
        self.plots.busy.connect(self._plots_busy)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(left)
        split.addWidget(self.plots)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([820, 680])
        self.setCentralWidget(split)

        # --- status bar: timings, model, progress + cancel
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setMaximumWidth(260)
        self.progress.setVisible(False)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._cancel_job)
        self.timing_label = QLabel("")
        self.timing_label.setToolTip("Measured timings for the last run (details in Help → About)")
        self.model_label = QLabel("")
        self.statusBar().addPermanentWidget(self.timing_label)
        self.statusBar().addPermanentWidget(self.model_label)
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().addPermanentWidget(self.cancel_btn)

    def _build_menus(self):
        mb = self.menuBar()
        f = mb.addMenu("&File")
        self.act_open = QAction("Open flows CSV…", self, shortcut=QKeySequence.StandardKey.Open)
        self.act_open.triggered.connect(self.open_csv_dialog)
        self.act_open_review = QAction("Open review…", self)
        self.act_open_review.triggered.connect(self.open_review_dialog)
        self.act_save_review = QAction("Save review…", self, shortcut=QKeySequence.StandardKey.Save)
        self.act_save_review.triggered.connect(self.save_review_dialog)
        self.act_export = QAction("Export results CSV…", self, shortcut=QKeySequence("Ctrl+E"))
        self.act_export.triggered.connect(self.export_dialog)
        self.act_alerts = QAction("Export alerts for SIEM…", self)
        self.act_alerts.triggered.connect(self.export_alerts_dialog)
        self.act_feedback = QAction("Export labelled feedback…", self)
        self.act_feedback.triggered.connect(self.export_feedback_dialog)
        self.data_actions = [self.act_open_review, self.act_save_review, self.act_export,
                             self.act_alerts, self.act_feedback]
        for a in self.data_actions:
            a.setEnabled(False)
        act_model = QAction("Open model…", self)
        act_model.triggered.connect(self.open_model_dialog)
        act_comparison = QAction("Open comparison results…", self)
        act_comparison.setToolTip("feature_set_comparison.csv from notebook section 9c")
        act_comparison.triggered.connect(self.open_comparison_dialog)
        act_exit = QAction("Exit", self, shortcut=QKeySequence.StandardKey.Quit)
        act_exit.triggered.connect(self.close)
        for group in ([self.act_open], [self.act_open_review, self.act_save_review],
                      [self.act_export, self.act_alerts, self.act_feedback], [act_model, act_comparison],
                      [act_exit]):
            for a in group:
                f.addAction(a)
            if a is not act_exit:
                f.addSeparator()

        self.model_menu = mb.addMenu("&Model")
        self.model_group = QActionGroup(self)
        self.model_group.setExclusive(True)

        h = mb.addMenu("&Help")
        features = QAction("Features…", self)
        features.triggered.connect(self.show_features)
        about = QAction("About / Model card", self, shortcut=QKeySequence("F1"))
        about.triggered.connect(self.show_about)
        h.addAction(features)
        h.addAction(about)

        tb = QToolBar("Main")
        tb.setMovable(False)
        for a in (self.act_open, self.act_save_review, self.act_export, self.act_alerts):
            tb.addAction(a)
        tb.addSeparator()
        tb.addAction(features)
        tb.addAction(about)
        self.addToolBar(tb)

    # =========================================================================== models
    def _rebuild_model_menu(self):
        self.model_menu.clear()
        for a in self.model_group.actions():
            self.model_group.removeAction(a)
        paths = list_models(self.models_dir)
        if self.bundle and self.bundle.meta_path and self.bundle.meta_path not in paths:
            paths.append(self.bundle.meta_path)   # opened from elsewhere
        for p in paths:
            a = QAction(p.name.removesuffix(".meta.json"), self, checkable=True)
            a.setData(str(p))
            a.setChecked(self.bundle is not None and self.bundle.meta_path == p)
            a.triggered.connect(lambda _=False, p=p: self.set_model(p))
            self.model_group.addAction(a)
            self.model_menu.addAction(a)
        if not paths:
            a = QAction("(no models found: run train/train_model.py)", self)
            a.setEnabled(False)
            self.model_menu.addAction(a)
        self.model_menu.addSeparator()
        more = QAction("Open model…", self)
        more.triggered.connect(self.open_model_dialog)
        self.model_menu.addAction(more)

    def _load_default_model(self):
        paths = list_models(self.models_dir)
        by_name = {p.name.removesuffix(".meta.json"): p for p in paths}
        pick = next((by_name[n] for n in DEFAULT_MODELS if n in by_name), paths[0] if paths else None)
        if pick:
            self.set_model(pick)
        else:
            self._rebuild_model_menu()
            self.model_label.setText("No model loaded")
            QMessageBox.information(self, "No model", f"No trained models found in {self.models_dir}.\n"
                                    "Train one with: python train/train_model.py --mode all_tools")

    def set_model(self, meta_path: Path, rescore: bool = True):
        if self._job is not None:
            QMessageBox.information(self, "Busy", "Wait for the current job to finish (or cancel it) "
                                    "before switching models.")
            self._rebuild_model_menu()
            return
        try:
            bundle = load_bundle(Path(meta_path))
        except Exception as e:
            log.exception("model load failed")
            QMessageBox.critical(self, "Could not open model", f"{Path(meta_path).name}:\n{e}")
            self._rebuild_model_menu()
            return
        self.bundle = bundle
        self.model_label.setText(f"Model: {bundle.name}, {summary(bundle.features)} [{bundle.version}]")
        self.model_label.setToolTip(bundle.title)
        self._rebuild_model_menu()
        log.info("model %s (version %s, %s) loaded", bundle.name, bundle.version, summary(bundle.features))
        if rescore and self.clean_df is not None:
            self._start_scoring(self.clean_df, self.results.source if self.results else "")

    def open_model_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open model metadata", str(self.models_dir),
                                              "Model metadata (*.meta.json)")
        if path:
            self.set_model(Path(path))

    # ============================================================================= data
    def open_csv_dialog(self):
        if not self._maybe_save_review():
            return
        start = self.settings.value("last_csv_dir", str(DATA_DIR))
        path, _ = QFileDialog.getOpenFileName(self, "Open CICFlowMeter flows CSV", start, "CSV files (*.csv);;All files (*)")
        if path:
            self.settings.setValue("last_csv_dir", str(Path(path).parent))
            self.open_csv(Path(path))

    def open_csv(self, path: Path):
        path = Path(path)
        if self.bundle is None:
            QMessageBox.warning(self, "No model", "Load a model first (Model menu).")
            return
        if self._job is not None:
            QMessageBox.information(self, "Busy", "Another job is running. Cancel it first.")
            return
        try:
            header = read_header(path)
        except Exception as e:
            QMessageBox.critical(self, "Could not read file", f"{path.name}:\n{e}")
            return
        missing = missing_columns(header, self.bundle.features)
        if missing:
            alternative = self._missing_dialog(path, missing, header)
            if alternative is not None:           # user chose a model that does not need them
                self.set_model(alternative, rescore=False)
                self.open_csv(path)
            return

        bundle = self.bundle   # the worker must not read window attributes

        def work(progress, cancelled):
            with Stopwatch() as load_sw:
                df = read_flows(path, extra_columns=tuple(TRACING_COLUMNS), required_for=bundle.features,
                                progress=lambda f: progress(0.9 * f), cancelled=cancelled)
            if cancelled():
                return None
            with Stopwatch() as score_sw:
                X, scores = score(bundle, df)
            X_all = build_all(df)
            progress(1.0)
            return df, X, scores, load_sw.seconds, score_sw.seconds, X_all

        self._run_job(work, f"Loading {path.name}", lambda out: self._loaded(out, path))

    def _start_scoring(self, df, source: str):
        bundle = self.bundle
        if missing_columns(df.columns, bundle.features):
            missing = missing_columns(df.columns, bundle.features)
            QMessageBox.warning(self, "Model needs other columns",
                                f"{bundle.name} needs column(s) the loaded file does not have:\n\n  • "
                                + "\n  • ".join(missing) + "\n\nThe loaded results were not re-scored.")
            return

        def work(progress, cancelled):
            with Stopwatch() as sw:
                X, scores = score(bundle, df)
            return df, X, scores, None, sw.seconds, build_all(df)

        self._run_job(work, f"Scoring with {bundle.name}",
                      lambda out: self._loaded(out, self.source_path, keep_review=True))

    def _run_job(self, fn, label: str, on_result):
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.progress.setFormat(f"{label} %p%")
        self.cancel_btn.setVisible(True)
        self.act_open.setEnabled(False)
        self.statusBar().showMessage(label + "…")

        def finished():
            self._job = None
            self.progress.setVisible(False)
            self.cancel_btn.setVisible(False)
            self.act_open.setEnabled(True)

        self._job = self.jobs.start(
            fn, name=label,
            on_progress=lambda f: self.progress.setValue(int(f * 1000)),
            on_result=lambda out: out is not None and on_result(out),
            on_error=self._job_error,
            on_cancelled=lambda: self.statusBar().showMessage("Cancelled.", 5000),
            on_finished=finished)

    def _cancel_job(self):
        if self._job is not None:
            self._job.cancel()
            self.statusBar().showMessage("Cancelling…")

    def _job_error(self, e, tb):
        if isinstance(e, MissingColumnsError):
            self._missing_dialog(None, e.missing)
            return
        QMessageBox.critical(self, "Something went wrong", f"{e}\n\nDetails are in logs/app.log.")

    def _models_not_needing(self, header) -> list[Path]:
        """Models in the models folder whose required raw columns the CSV header has."""
        out = []
        for name, meta in read_metas(self.models_dir):
            if not missing_columns(header, model_columns(meta)):
                out.append(self.models_dir / f"{name}.meta.json")
        return out

    def _missing_dialog(self, path, missing, header=None) -> Path | None:
        """Explain which columns are missing. If another model can score the file, offer it
        (never score with fewer features silently). Returns the chosen model's meta path."""
        name = path.name if path else "The file"
        model = self.bundle.name if self.bundle else "the active model"
        text = (f"{name} cannot be scored with {model} because these required column(s) are missing:\n\n  • "
                + "\n  • ".join(missing))
        options = self._models_not_needing(header) if header is not None else []
        defaults = [self.models_dir / f"{n}.meta.json" for n in DEFAULT_MODELS]   # most columns first
        preferred = next((p for p in defaults if p in options), options[0] if options else None)
        if preferred is None:
            QMessageBox.critical(self, "Missing columns",
                                 text + "\n\nNo trained model can score this file. The app needs CICFlowMeter "
                                        "flow CSVs (as in CSE-CIC-IDS2018).")
            return None
        alt = preferred.name.removesuffix(".meta.json")
        box = QMessageBox(QMessageBox.Icon.Warning, "Missing columns",
                          text + f"\n\nThe model '{alt}' does not need these columns "
                          f"({summary(model_columns(read_meta(preferred)))}). Score the file with it instead?",
                          parent=self)
        use = box.addButton(f"Use {alt}", QMessageBox.ButtonRole.AcceptRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        return preferred if box.clickedButton() is use else None

    def open_comparison_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open feature-set comparison results", str(self.models_dir),
                                              "CSV files (*.csv)")
        if path:
            self.plots.set_file(FILE_KIND, Path(path))
            for i, t in enumerate(self.plots.chart_tabs):
                if t.plugin.name == "Feature-set comparison":
                    self.plots.tabs.setCurrentIndex(i)
            self.statusBar().showMessage(f"Comparison results: {Path(path).name}", 10000)

    def _loaded(self, out, path: Path, keep_review: bool = False):
        df, X, scores, load_s, score_s, X_all = out
        self._n_extra_missing = int((extra_missing_mask(X) & ~np.isnan(scores)).sum())
        old = self.results
        self.clean_df, self.source_path = df, Path(path)
        source = self.source_path.name
        labels = df[LABEL].astype(str).to_numpy() if LABEL in df.columns else None
        tools = tools_from_labels(df[LABEL]).to_numpy() if LABEL in df.columns else None
        stamps = df[TIME].astype(str).to_numpy() if TIME in df.columns else None
        tracing = {short: df[col].astype(str).to_numpy() for col, short in TRACING_COLUMNS.items()
                   if col in df.columns}
        review = old.review if keep_review and old is not None and len(old) == len(df) else None
        self.results = ResultsData(rows=df["row"].to_numpy(), scores=scores, X=X, labels=labels, tools=tools,
                                   timestamps=stamps, source=source, tracing=tracing, review=review)
        self.table_model.threshold = self.thr.value()
        self.table_model.set_results(self.results)
        self.table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self._filters_changed()
        self._data_id += 1

        # timings (measured in the worker with time.perf_counter)
        if load_s is not None:
            self.timings.load_s, self.timings.load_rows = load_s, len(df)
        self.timings.score_s, self.timings.score_rows = score_s, int((~np.isnan(scores)).sum())
        self.timings.shap.clear()
        for line in self.timings.lines():
            log.info("timing: %s", line)
        self._show_timings()

        self.cache.reset(self.bundle.model, X, self._data_id)
        ctx = ChartContext(model=self.bundle.model, model_title=self.bundle.title, X=X, scores=scores,
                           threshold=self.thr.value(), tools=tools, row_numbers=self.results.rows,
                           cache=self.cache, model_meta=self.bundle.meta, model_name=self.bundle.name,
                           models_dir=self.models_dir, X_all=X_all)
        self.plots.set_context(ctx)
        for a in self.data_actions:
            a.setEnabled(True)
        self.setWindowTitle(f"Explainable DDoS detection: {source}")
        n_bad = int(np.isnan(scores).sum())
        msg = f"Loaded {len(scores):,} flows from {source}"
        if n_bad:
            msg += f"; {n_bad:,} not scored (invalid values)"
        self.statusBar().showMessage(msg, 10000)
        self._update_summary()
        log.info(msg)

    def _plots_busy(self, text: str):
        self.statusBar().showMessage(text)
        if not text:
            self._show_timings()

    def _show_timings(self):
        self.timing_label.setText(self.timings.short())

    # ======================================================================= controls
    def _threshold_changed(self, t: float):
        self.slider.blockSignals(True)
        self.slider.setValue(int(round(t * 1000)))
        self.slider.blockSignals(False)
        self.table_model.set_threshold(t)
        self.plots.set_threshold(t)
        self._update_summary()

    def _filters_changed(self, *_):
        codes = {c for c, cb in ((CODE_BENIGN, self.f_benign), (CODE_DDOS, self.f_ddos),
                                 (CODE_NOT_SCORED, self.f_ns)) if cb.isChecked()}
        lo, hi = self.s_lo.value(), self.s_hi.value()
        if lo > hi:
            lo, hi = hi, lo
        self.table_model.set_filter(codes, (lo, hi))
        self._update_summary()

    def _reset_filters(self):
        for cb in (self.f_benign, self.f_ddos, self.f_ns):
            cb.setChecked(True)
        self.s_lo.setValue(0.0)
        self.s_hi.setValue(1.0)

    def _row_changed(self, current, _previous):
        if not current.isValid():
            return
        self.plots.select_row(self.table_model.position(current.row()))

    def _update_summary(self):
        r = self.results
        if r is None:
            return
        codes = self.table_model.codes
        n, n_ddos, n_ns = len(codes), int((codes == CODE_DDOS).sum()), int((codes == CODE_NOT_SCORED).sum())
        n_rev = int((r.review.verdicts != rv.UNREVIEWED).sum())
        parts = [f"<b>{n:,}</b> flows", f"<b>{n_ddos:,}</b> flagged DDoS", f"<b>{n_ns:,}</b> not scored (invalid values)"]
        if self._n_extra_missing:   # allowed: XGBoost handles missing values in features 8-15
            parts.append(f"<b>{self._n_extra_missing:,}</b> flows have missing values in features 8 to 15")
        parts += [f"<b>{n_rev:,}</b> reviewed", f"showing {self.table_model.rowCount():,}"]
        text = " · ".join(parts)
        if r.tools is not None:
            m = label_metrics(r.scores, r.tools, self.thr.value())
            rec = ", ".join(f"{t} {v:.3f}" for t, v in m["recall"].items())
            line = []
            if m["recall_all"] is not None:
                line.append(f"Recall (Label present): all attacks {m['recall_all']:.3f}" + (f" ({rec})" if rec else ""))
            if m["fpr"] is not None:
                line.append(f"false positives {m['false_positives']:,} of {m['n_benign']:,} benign "
                            f"(rate {m['fpr']:.4f})")
            if line:
                text += "<br>" + " · ".join(line) + f" at threshold {self.thr.value():.3f}"
        self.summary.setText(text)

    # =================================================================== analyst review
    def _selected_position(self) -> int | None:
        idx = self.table.selectionModel().currentIndex()
        if self.results is None or not idx.isValid():
            return None
        return self.table_model.position(idx.row())

    def _table_menu(self, point):
        idx = self.table.indexAt(point)
        if self.results is None or not idx.isValid():
            return
        self.table.selectRow(idx.row())
        menu = QMenu(self)
        for a in self.verdict_actions.values():
            menu.addAction(a)
        menu.addSeparator()
        menu.addAction(self.note_action)
        menu.exec(self.table.viewport().mapToGlobal(point))

    def set_verdict_selected(self, code: int):
        pos = self._selected_position()
        if pos is None:
            return
        self.table_model.set_review(pos, verdict=code)
        self._update_summary()

    def edit_note_selected(self):
        pos = self._selected_position()
        if pos is None:
            return
        current = self.results.review.notes.get(pos, "")
        text, ok = QInputDialog.getMultiLineText(self, "Analyst note",
                                                 f"Note for row {self.results.rows[pos]}:", current)
        if ok:
            self.table_model.set_review(pos, note=text)

    def _default_path(self, key: str, filename: str) -> str:
        base = self.settings.value(key) or (str(self.source_path.parent) if self.source_path else str(Path.cwd()))
        return str(Path(base) / filename)

    def save_review_dialog(self) -> bool:
        if self.results is None:
            return False
        start = self._default_path("last_review_dir", rv.default_review_name(self.results.source))
        path, _ = QFileDialog.getSaveFileName(self, "Save review", start, "Review files (*.json)")
        if not path:
            return False
        self.settings.setValue("last_review_dir", str(Path(path).parent))
        return self.save_review(Path(path))

    def save_review(self, path: Path) -> bool:
        r = self.results
        try:
            n = rv.save_review(path, r.review, r.rows, r.scores, FLAG_NAMES[self.table_model.codes],
                               self.thr.value(), r.source, self.bundle.name, self.bundle.version)
        except OSError as e:
            QMessageBox.critical(self, "Save failed", f"Could not save the review:\n{e}")
            return False
        self.statusBar().showMessage(f"Saved {n:,} reviewed flow(s) to {Path(path).name}", 10000)
        log.info("review saved: %s (%d rows)", path, n)
        return True

    def open_review_dialog(self):
        if self.results is None:
            return
        start = self._default_path("last_review_dir", rv.default_review_name(self.results.source))
        path, _ = QFileDialog.getOpenFileName(self, "Open review", start, "Review files (*.json)")
        if path:
            self.settings.setValue("last_review_dir", str(Path(path).parent))
            self.open_review(Path(path))

    def open_review(self, path: Path):
        r = self.results
        try:
            rep = rv.load_review(path, r.review, r.rows, r.source)
        except (OSError, ValueError, KeyError) as e:
            QMessageBox.critical(self, "Could not open review", f"{Path(path).name}:\n{e}")
            return
        self.table_model.review_reloaded()
        self._update_summary()
        msg = f"Restored {rep.applied:,} verdict(s)/note(s) from {Path(path).name}."
        if rep.other_source or rep.missing_rows:
            details = []
            if rep.other_source:
                details.append(f"The review was saved for '{rep.file_source}', not '{r.source}'.")
            if rep.missing_rows:
                details.append(f"{len(rep.missing_rows):,} reviewed row(s) are not in the loaded file "
                               f"(e.g. row {rep.missing_rows[0]}).")
            QMessageBox.warning(self, "Review loaded with warnings", msg + "\n\n" + "\n".join(details))
        self.statusBar().showMessage(msg, 10000)

    def _maybe_save_review(self) -> bool:
        """Ask to save unsaved verdicts. Returns False if the user cancels."""
        if self.results is None or not self.results.review.dirty:
            return True
        ans = QMessageBox.question(
            self, "Unsaved review", "You have unsaved analyst verdicts or notes. Save them first?",
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel)
        if ans == QMessageBox.StandardButton.Save:
            return self.save_review_dialog()
        return ans == QMessageBox.StandardButton.Discard

    # ========================================================================== export
    def export_dialog(self):
        if self.results is None:
            return
        stem = Path(self.results.source).stem or "results"
        start = self._default_path("last_export_dir", f"{stem}_scored.csv")
        path, _ = QFileDialog.getSaveFileName(self, "Export results CSV", start, "CSV files (*.csv)")
        if path:
            self.settings.setValue("last_export_dir", str(Path(path).parent))
            self.export_csv(Path(path))

    def export_csv(self, path: Path):
        frame = self.table_model.export_frame()   # snapshot taken on the UI thread

        def work(progress, cancelled):
            frame.to_csv(path, index=False)
            return path

        self._run_job(work, "Exporting", lambda p: self.statusBar().showMessage(f"Exported {p}", 10000))

    def export_alerts_dialog(self):
        if self.results is None:
            return
        n = int((self.table_model.codes == CODE_DDOS).sum())
        if n == 0:
            QMessageBox.information(self, "No alerts", "No flows are flagged DDoS at the current threshold.")
            return
        stem = Path(self.results.source).stem
        start = self._default_path("last_export_dir", f"alerts_{stem}.jsonl")
        path, _ = QFileDialog.getSaveFileName(self, f"Export {n:,} alerts (writes .csv and .jsonl)", start,
                                              "JSON Lines (*.jsonl);;CSV (*.csv)")
        if path:
            self.settings.setValue("last_export_dir", str(Path(path).parent))
            self.export_alerts(Path(path))

    def export_alerts(self, path: Path):
        r, bundle, threshold = self.results, self.bundle, self.thr.value()
        flags = FLAG_NAMES[self.table_model.codes]
        positions = np.flatnonzero(self.table_model.codes == CODE_DDOS)
        tracing = dict(r.tracing)
        if r.timestamps is not None:
            tracing["timestamp"] = r.timestamps
        names = list(r.X.columns)

        def work(progress, cancelled):
            top3, chunk = [], 50_000
            for start in range(0, len(positions), chunk):   # top SHAP features, in chunks for progress
                if cancelled():
                    return None
                part = positions[start:start + chunk]
                top3 += top_features(contributions(bundle.model, r.X.iloc[part]), names)
                progress(0.9 * min(1.0, (start + chunk) / len(positions)))
            recs = rv.alert_records(positions, r.rows, r.scores, flags, threshold, r.source,
                                    bundle.name, bundle.version, top3, tracing)
            return rv.write_alerts(path, recs), len(recs)

        def done(out):
            (csv_path, jsonl_path), n = out
            log.info("alerts exported: %d to %s and %s", n, csv_path, jsonl_path)
            self.statusBar().showMessage(f"Exported {n:,} alerts to {csv_path.name} and {jsonl_path.name}", 10000)

        self._run_job(work, "Exporting alerts", done)

    def export_feedback_dialog(self):
        if self.results is None:
            return
        v = self.results.review.verdicts
        n = int(np.isin(v, list(rv.FEEDBACK_LABEL)).sum())
        if n == 0:
            QMessageBox.information(self, "No labelled feedback",
                                    "No flows are marked 'confirmed attack' or 'false positive' yet.\n"
                                    "Right-click a row to set an analyst verdict.")
            return
        stem = Path(self.results.source).stem
        start = self._default_path("last_export_dir", f"feedback_{stem}.csv")
        path, _ = QFileDialog.getSaveFileName(self, "Export labelled feedback", start, "CSV files (*.csv)")
        if path:
            self.settings.setValue("last_export_dir", str(Path(path).parent))
            self.export_feedback(Path(path))

    def export_feedback(self, path: Path):
        r = self.results
        frame = rv.feedback_frame(r.review, r.X, r.rows, r.source)
        frame.to_csv(path, index=False)
        log.info("feedback exported: %d rows to %s", len(frame), path)
        self.statusBar().showMessage(f"Exported {len(frame):,} labelled flows to {Path(path).name} "
                                     "(unsure/unreviewed excluded)", 10000)

    # =========================================================================== dialogs
    def show_about(self):
        AboutDialog(self.bundle.meta if self.bundle else None, self, timings=self.timings,
                    version=self.bundle.version if self.bundle else "", models_dir=self.models_dir).exec()

    def show_features(self):
        FeaturesDialog(self).exec()

    def closeEvent(self, event):
        if not self._maybe_save_review():
            event.ignore()
            return
        if self._job is not None:
            self._job.cancel()
        self.jobs.wait(3000)
        self.plots.jobs.wait(3000)
        super().closeEvent(event)
