FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
# Runtime install only (with the optional signing extra); no dev tooling, no git.
RUN pip install --no-cache-dir ".[signing]" \
    && useradd --create-home --uid 10001 policy \
    && mkdir -p /app/policies /app/results \
    && chown policy:policy /app/policies /app/results
USER policy
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["toolkit-policy"]
CMD ["--help"]
