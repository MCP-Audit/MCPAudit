# Behavioral SAST fixtures

Small handler snippets used to validate description/code mismatch and taint-flow detection across Python, TypeScript, Go, and Rust.

## Run the eval corpus

```bash
uv run python scripts/run_behavioral_eval.py
uv run python scripts/run_behavioral_eval.py --json
```

The canonical corpus lives in `eval/behavioral/cases.json` with file-backed handlers under `eval/behavioral/handlers/`.

## Scan a fixture directly

Behavioral analysis runs as part of the default analyzer set when tool handlers are discovered:

```bash
uv run mcts scan examples/behavioral-fixtures/python_mismatch/server.py --format json
```

For Go/Rust snippets, pass handler source via static discovery or include `.go`/`.rs` files in the repository tree.
