# Policy Test Bench - Deployment Guide

## ðŸš€ Quick Start

### Docker Deployment (Recommended)

```bash
cd policy-test-bench
docker-compose up -d
docker-compose exec policy-test toolkit-policy-test run --policy policies/my-policy.json
```

### Local Installation

```bash
pip install -e ".[dev]"
toolkit-policy-test --version
pytest
```

## ðŸ”§ Configuration

See `.env.example` for all options.

**Key Settings:**
- `STRICT_MODE`: Enable strict policy enforcement
- `ENABLE_AUDIT_LOG`: Enable audit logging

## ðŸ“Š Production Deployment

### CI/CD Integration

```yaml
- name: Test Policy Compliance
  run: toolkit-policy-test run --policy $POLICY_FILE
```

### Monitoring

```python
from toolkit_policy_test.monitoring import get_health_status
status = get_health_status()
```

## ðŸ“ž Support

- Documentation: [README.md](README.md)
- Support: <support-email>



