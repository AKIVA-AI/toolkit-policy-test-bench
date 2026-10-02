# Importer fixtures

Real output files produced by each tool on 2026-09-26 in a throwaway `python:3.12-slim`
/ `node:22-slim` container, with no model and no network calls to any LLM. The
importer tests read these files unchanged, except where noted.

| File | Tool and version | How it was produced |
| ---- | ---------------- | ------------------- |
| `garak.report.jsonl` | garak 0.17.0 | `python -m garak --model_type test.Repeat --probes dan.Dan_11_0,promptinject.HijackHateHumans,leakreplay.LiteratureCloze --generations 1 --report_prefix sample`. The full report is 4.7 MB (1,026 attempt lines), so this fixture keeps the `init`, `eval` and `completion` entries and the first three evaluated (`status: 2`) attempts per probe. Kept lines are byte-for-byte unchanged. |
| `garak.capped.report.jsonl` | garak 0.17.0 | Same generator with `--config cap.yaml` (`run.soft_probe_prompt_cap: 4`, `run.generations: 2`) and probes `apikey.GetKey,dan.Dan_11_0,encoding.InjectBase64,leakreplay.LiteratureCloze,promptinject.HijackHateHumans`. Keeps `init`, `eval`, `completion` and **every** evaluated attempt, so the importer's counts can be checked against the `eval` entries garak wrote itself. Kept lines are unchanged. |
| `promptfoo.results.json` | promptfoo 0.123.1 | `promptfoo eval -c promptfoo.config.yaml -o promptfoo.results.json` with the offline `echo` provider. The tests carry red-team `pluginId` / `strategyId` / `severity` metadata in the same place `promptfoo redteam run` puts it. |
| `pyrit.scores.json` | PyRIT 1.1.0 | `pyrit_generate.py`: three conversations stored in SQLite memory and scored with `SubStringScorer`, then `[s.model_dump(mode="json") for s in memory.get_scores(...)]`. |
| `pyrit.memory.sql` | PyRIT 1.1.0 | The `PromptMemoryEntries` and `ScoreEntries` tables of the same `pyrit.db`, dumped with `sqlite3` `iterdump()` so the fixture is text. Tests load it into a fresh SQLite file. |

`pyrit_generate.py` needs PyRIT installed and is not part of the test suite.
