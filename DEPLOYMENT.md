# Policy Test Bench - Deployment Guide

## Quick Start

### Docker Deployment (Recommended)

```bash
docker-compose up -d
docker-compose exec policy-test toolkit-policy run --suite /app/policies/suite.zip --predictions /app/policies/preds.jsonl
```

### Local Installation

```bash
pip install -e ".[dev]"
toolkit-policy --version
pytest
```

## Configuration

See `.env.example` for all options.

**Key Settings:**

- `LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)

## Production Deployment

### CI/CD Integration

```yaml
- name: Run Policy Suite
  run: toolkit-policy run --suite $SUITE_PATH --predictions $PREDICTIONS_PATH --out report.json

- name: Compare Against Baseline
  run: toolkit-policy compare --baseline baseline.json --candidate report.json
```

## Support

- Documentation: [README.md](README.md)
