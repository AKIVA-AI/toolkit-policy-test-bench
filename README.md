# Toolkit Policy Test Bench

A lightweight red-team and compliance regression harness for LLM apps.

It helps teams continuously test model/app outputs for:

- **PII leakage** - email/phone/SSN/credit cards
- **Secret leakage** - API key patterns, JWTs, AWS keys, etc.
- **Policy constraints** - must/must-not content, regex rules, max output length
- **JSON output shape checks** - required keys, extra keys
- **Custom detectors** - register your own PII/secret patterns via plugins

It is designed to be safe to open source as a standalone utility. A commercial/Pro version can add governance, tenant-aware policies, signed packs, and audit exports.

## Install (dev)

```bash
pip install -e ".[dev]"
pytest -q
```

For Ed25519 signing support:

```bash
pip install -e ".[signing]"
```

## Concepts

- **Suite**: versioned set of cases and check configuration (`suite.json` + `cases.jsonl`), optionally zipped into a pack.
- **Case**: `{ "id": "...", "input": ..., "tags": [...] }` (input is typically chat messages).
- **Predictions**: JSONL `{ "id": "...", "prediction": "..." }`.
- **Report**: JSON output with per-case findings and aggregated metrics.
- **Pack**: Zip archive of a suite with manifest (SHA-256 hashes) and optional Ed25519 signature.

## Quickstart

Create a suite pack zip:

```bash
toolkit-policy pack create --suite-dir examples/suite --out packs/policy.zip
```

Verify pack integrity (hashes):

```bash
toolkit-policy pack verify --suite packs/policy.zip
```

Sign suite packs (optional):

```bash
toolkit-policy keygen --private-key ed25519_priv.pem --public-key ed25519_pub.pem
toolkit-policy pack sign --suite packs/policy.zip --private-key ed25519_priv.pem --out packs/policy.sig.json
toolkit-policy pack verify-signature --suite packs/policy.zip --signature packs/policy.sig.json --public-key ed25519_pub.pem
```

Run evaluation and emit a report:

```bash
toolkit-policy run --suite packs/policy.zip --predictions examples/preds.jsonl --out report.json
```

Compare a candidate report to a baseline report (CI gating):

```bash
toolkit-policy compare --baseline baseline.json --candidate report.json
```

## Complete CLI Reference

### Global flags

| Flag | Description |
| ---- | ----------- |
| `--version` | Print version and exit |
| `-v, --verbose` | Enable DEBUG-level logging to stderr |
| `--log-format {text,json}` | Log output format (default: `text`) |

### `toolkit-policy run`

Run a policy suite against predictions.

```bash
toolkit-policy run --suite <path> --predictions <path> [--out <path>] [--format {json,table}]
```

| Flag | Required | Description |
| ---- | -------- | ----------- |
| `--suite` | Yes | Suite path (directory or `.zip` pack) |
| `--predictions` | Yes | Predictions JSONL file (`id` + `prediction`) |
| `--out` | No | Write report JSON to file |
| `--format` | No | Output format: `json` (default) or `table` |

### `toolkit-policy compare`

Compare a candidate report against a baseline report for CI gating.

```bash
toolkit-policy compare --baseline <path> --candidate <path> [--format {json,table}] [--max-fail-rate-increase-pct N] [--max-pii-hits-increase N] [--max-secret-hits-increase N]
```

| Flag | Required | Description |
| ---- | -------- | ----------- |
| `--baseline` | Yes | Baseline report JSON |
| `--candidate` | Yes | Candidate report JSON |
| `--format` | No | Output format: `json` (default) or `table` |
| `--max-fail-rate-increase-pct` | No | Max fail rate increase % (default: 0.0) |
| `--max-pii-hits-increase` | No | Max PII hits increase (default: 0) |
| `--max-secret-hits-increase` | No | Max secret hits increase (default: 0) |

### `toolkit-policy validate-report`

Validate a policy report JSON has the expected shape.

```bash
toolkit-policy validate-report --report <path>
```

### `toolkit-policy pack create`

Create a suite pack zip from a suite directory.

```bash
toolkit-policy pack create --suite-dir <path> --out <path>
```

### `toolkit-policy pack inspect`

Inspect a suite (directory or zip) and print its metadata as JSON.

```bash
toolkit-policy pack inspect --suite <path>
```

### `toolkit-policy pack verify`

Verify pack integrity by checking SHA-256 hashes in the manifest.

```bash
toolkit-policy pack verify --suite <path>
```

### `toolkit-policy pack sign`

Sign a pack zip with an Ed25519 private key (detached signature).

```bash
toolkit-policy pack sign --suite <path> --private-key <path> [--out <path>]
```

### `toolkit-policy pack verify-signature`

Verify a detached Ed25519 signature for a pack.

```bash
toolkit-policy pack verify-signature --suite <path> --signature <path> --public-key <path>
```

### `toolkit-policy keygen`

Generate an Ed25519 keypair for signing suite packs.

```bash
toolkit-policy keygen --private-key <path> --public-key <path>
```

## Custom Detector Plugins

Register custom PII or secret detectors programmatically:

```python
import re
from toolkit_policy_test_bench.plugins import registry, DetectorPlugin

def detect_mrn(text: str) -> dict[str, int]:
    return {"medical_record": len(re.findall(r"MRN-\d{8}", text))}

registry.register(DetectorPlugin(
    name="medical_record",
    kind="pii",
    detect=detect_mrn,
))
```

Or load patterns from a JSON file:

```json
{
    "detectors": [
        {"name": "internal_id", "kind": "pii", "pattern": "INT-\\d{6}"},
        {"name": "github_token", "kind": "secret", "pattern": "ghp_[A-Za-z0-9]{36}"}
    ]
}
```

```python
from pathlib import Path
from toolkit_policy_test_bench.plugins import registry
registry.load_patterns_file(Path("custom_patterns.json"))
```

Custom detectors are automatically invoked during `run_suite` when PII or secret detection is enabled.

## CI Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0` | Success |
| `2` | CLI error (bad arguments, file not found) |
| `3` | Unexpected error |
| `4` | Validation failed (compare budget exceeded, report invalid) |

## CI Integration Example

```yaml
- name: Run policy tests
  run: |
    toolkit-policy run \
      --suite packs/policy.zip \
      --predictions preds.jsonl \
      --out report.json
    toolkit-policy compare \
      --baseline baseline.json \
      --candidate report.json \
      --max-fail-rate-increase-pct 0.0
```

## License

MIT License - see LICENSE file for details.
