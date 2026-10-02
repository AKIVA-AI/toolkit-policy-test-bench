# Deployment

## CI

Install from PyPI in the job, then run the suite. `run` fails the step when a case
fails; see the README "CI example" for a baseline-comparison variant.

```yaml
- run: pip install toolkit-policy-test-bench
- run: toolkit-policy run --suite packs/policy.zip --predictions preds.jsonl --out report.json
```

For signed packs, add `--signature <sig.json> --public-key <pub.pem>` to `run` and
install the signing extra (`pip install "toolkit-policy-test-bench[signing]"`).

In GitHub Actions you can use the bundled action instead; see the README "GitHub
Action" section.

## Docker

```bash
docker compose build
docker compose run --rm policy-test run --suite /app/policies/suite.zip \
  --predictions /app/policies/preds.jsonl --out /app/results/report.json
```

`./policies` and `./results` are mounted into the container. The image runs as a
non-root user (uid 10001), so both directories must be writable by that uid.

## Configuration

The tool reads no environment variables of its own. Everything is set through CLI
flags and the suite's `checks`. The optional `--refusal-judge` uses LiteLLM, which reads
the model provider's usual variables (for example `OPENAI_API_KEY`). Logging: `--verbose` and `--log-format json`.
