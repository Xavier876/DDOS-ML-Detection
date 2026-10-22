"""Chart plugins. Every module in this package is imported so its @register runs."""
import importlib
import pkgutil

for _m in pkgutil.iter_modules(__path__):
    if _m.name != "base" and not _m.name.startswith("_"):
        importlib.import_module(f"{__name__}.{_m.name}")
