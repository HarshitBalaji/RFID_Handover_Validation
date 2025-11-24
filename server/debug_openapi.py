# debug_openapi.py
import traceback
import importlib
import sys

try:
    # import your FastAPI app
    mod = importlib.import_module("main")   # adjust if your module name is different
    app = getattr(mod, "app")
    # force OpenAPI generation
    spec = app.openapi()
    print("OpenAPI generation succeeded. Top-level info:")
    print("title:", spec.get("info", {}).get("title"))
    print("paths count:", len(spec.get("paths", {})))
    # optionally print a small sample of paths
    for i, p in enumerate(list(spec.get("paths", {}).keys())[:20]):
        print(" -", p)
    sys.exit(0)
except Exception as e:
    print("OpenAPI generation raised an exception:")
    traceback.print_exc()
    sys.exit(2)
