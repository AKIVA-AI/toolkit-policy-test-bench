# Policy Test Bench - Quick Start

## ðŸš€ Installation

```bash
pip install -e ".[dev]"
toolkit-policy-test --version
```

## ðŸ“ Basic Usage

```bash
# Test policy compliance
toolkit-policy-test run --policy policies/my-policy.json --out results.json
```

## ðŸ³ Docker Usage

```bash
docker-compose up -d
docker-compose exec policy-test toolkit-policy-test run --policy /app/policies/my-policy.json
```

## ðŸ“š Next Steps

- Read [README.md](README.md)
- Check [DEPLOYMENT.md](DEPLOYMENT.md)

---

**Ready to test AI policies!** ðŸš€


