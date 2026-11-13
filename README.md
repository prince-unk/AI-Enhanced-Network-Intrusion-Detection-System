# AI-Enhanced NIDS — Final Integration Package

This ZIP is a **merge package** for the three source files supplied for review. It is not a replacement for the entire repository: retain your existing `behavior_engine.py`, `.env`, Suricata rules, virtual environment, and other project assets.

## Files to merge

Replace these three files in the existing project directory:

- `app.py`
- `storage.py`
- `nids_core.py`

The package also includes:

- `tests/test_storage.py` — isolated SQLite regression tests.
- `docs/RETENTION_AND_TESTING.md` — design and verification notes.
- `requirements-nids.txt` — direct runtime dependencies used by the supplied app.
- `.env.example` — configuration template; never put a real API key in it.

## Merge steps (Parrot OS)

From the project root, extract this ZIP and allow it to overwrite the three source files. Keep your existing `behavior_engine.py` and `.env` untouched.

```bash
source .venv/bin/activate
python -m py_compile app.py storage.py nids_core.py
python -m unittest discover -s tests -v
streamlit run app.py
```

If your virtual environment has a different name, activate that environment instead. Install missing direct dependencies from `requirements-nids.txt` only if needed:

```bash
pip install -r requirements-nids.txt
```

## Configuration

Copy `.env.example` to `.env` only if you need a template. Set `GEMINI_API_KEY` locally and keep `.env` out of Git. `GEMINI_MODEL` defaults to `gemini-3.5-flash-lite`; `EVE_JSON` defaults to `/var/log/suricata/eve.json`.

## Important verification boundary

The uploaded source set contained `app.py`, `storage.py`, and `nids_core.py`; it did not contain `behavior_engine.py`, the full dependency lockfile, Suricata configuration, or the rest of the repository. This package preserves the existing `BehavioralDetector` interface and does not overwrite those missing project assets. A full end-to-end claim requires running the app in the user's actual repository and verifying live Suricata input there.
