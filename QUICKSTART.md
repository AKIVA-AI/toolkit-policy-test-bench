# Policy Test Bench - Quick Start

## Installation

```bash
pip install -e ".[dev]"
toolkit-policy --version
```

## Basic Usage

```bash
# Run a policy suite against predictions
toolkit-policy run --suite packs/policy.zip --predictions examples/preds.jsonl --out results.json
```

## Docker Usage

```bash
docker-compose up -d
docker-compose exec policy-test toolkit-policy run --suite /app/policies/suite.zip --predictions /app/policies/preds.jsonl
```

## Next Steps

- Read [README.md](README.md)
- Check [DEPLOYMENT.md](DEPLOYMENT.md)
