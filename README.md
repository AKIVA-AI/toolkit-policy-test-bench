# Toolkit Policy Test Bench

A lightweight red-team and compliance regression harness for LLM apps.

It helps teams continuously test model/app outputs for:

- **PII leakage** - email/phone/SSN/credit cards
- **Secret leakage** - API key patterns, JWTs, AWS keys, etc.
- **Policy constraints** - must/must-not content, regex rules, max output length
- **JSON output shape checks** - required keys, extra keys

It is designed to be safe to open source as a standalone utility. A commercial/Pro version can add governance, tenant-aware policies, signed packs, and audit exports.

## Install (dev)

```bash
pip install -e ".[dev]"
pytest -q
```

## Concepts

- **Suite**: versioned set of cases and check configuration (`suite.json` + `cases.jsonl`), optionally zipped into a pack.
- **Case**: `{ "id": "...", "input": ..., "tags": [...] }` (input is typically chat messages).
- **Predictions**: JSONL `{ "id": "...", "prediction": "..." }`.
- **Report**: JSON output with per-case findings and aggregated metrics.

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
pip install -e ".[signing]"
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

## CLI Commands

- `pack create` - Create a suite pack
- `pack verify` - Verify pack integrity
- `pack sign` - Sign suite packs
- `pack verify-signature` - Verify signatures
- `run` - Run evaluation
- `compare` - Compare reports for CI gating
- `keygen` - Generate signing keys

## CI exit codes

- `compare`: `0` = passed, `4` = failed budgets

## License

MIT License - see LICENSE file for details.
