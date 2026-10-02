# Quick Start

Install from source (not on PyPI yet):

```bash
git clone https://github.com/AKIVA-AI/toolkit-policy-test-bench.git
cd toolkit-policy-test-bench
pip install -e ".[signing]"
toolkit-policy --version
```

Run a suite against your app's predictions:

```bash
toolkit-policy run --suite path/to/suite --predictions preds.jsonl --out report.json
```

`run` exits 0 when every case passes and 4 when any case fails or any PII/secret is
found.

Import red-team results and file them as control evidence:

```bash
toolkit-policy import --source garak --input garak.report.jsonl --out garak.json
toolkit-policy evidence --report report.json --report garak.json --format markdown
```

See the [README](README.md) "5-minute example" for a complete walk-through on the
bundled `examples/support-bot`, the suite format and the CLI reference.
