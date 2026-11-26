r"""Rewrite `feature_groups` in every model's .meta.json from the registry (5 Nov 2026 renumbering).

    .\.venv\Scripts\python.exe DDoSDetector\scripts\renumber_model_metadata.py

The catalogue was renumbered so that features 1-6 are the default model's inputs. A model's inputs are its
`feature_columns` (unchanged); `feature_groups` is descriptive and is rebuilt here from the registry, with each
group's app number, its Week 3 document number and its columns. Nothing else in the metadata changes, and the model
files are not touched.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.features import groups_for  # noqa: E402
from app.core.model_store import list_models, model_columns  # noqa: E402
from app.paths import MODELS_DIR  # noqa: E402


def main() -> int:
    n = 0
    for p in list_models(MODELS_DIR):
        meta = json.loads(p.read_text(encoding="utf-8"))
        cols = model_columns(meta)
        meta["feature_groups"] = [{"number": g.number, "week3": g.week3, "key": g.key, "title": g.title,
                                   "columns": [c for c in g.output_columns if c in cols]} for g in groups_for(cols)]
        p.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        n += 1
    print(f"rewrote feature_groups in {n} metadata files under {MODELS_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
