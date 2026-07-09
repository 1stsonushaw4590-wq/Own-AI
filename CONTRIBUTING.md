# Contributing to Cyber-LLM

Thanks for your interest in contributing.

## Development setup

```bash
make venv && make deps
make install-hooks
make test          # must pass before any commit
```

## Pull request checklist

1. `make test` passes (13 tests)
2. New scripts compile (`python3 -m py_compile scripts/new_script.py`)
3. README updated if adding a new feature
4. No secrets or API keys committed

## Adding a new eval prompt

Edit `scripts/eval.py` → `BENIGN_PROMPTS` or `ABUSE_PROMPTS`:
```python
{"id": "my_test", "prompt": "...", "checks": ["keyword1", "keyword2"]}
```

## Adding a new dataset source

1. Add scraper to `scripts/scrape_dataset.py`
2. Output as alpaca JSONL to `data/raw/`
3. Run `python3 scripts/dataset_manager.py --build`

## Code style

- No comments unless asked
- `scripts/` are standalone (runnable with `python3 scripts/foo.py`)
- All paths anchored to repo root via `REPO_ROOT = Path(__file__).resolve().parent.parent`
