FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_NO_CACHE=1 \
    PATH="/app/.venv/bin:${PATH}" \
    PORT=8080

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check "uv==0.12.3" \
    && uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable \
    && /usr/local/bin/python -m pip uninstall --yes uv

USER 65532:65532
EXPOSE 8080

FROM runtime AS reference-stable
CMD ["controlgraph-canary", "serve-reference-stable"]

FROM runtime AS reference-candidate
CMD ["controlgraph-canary", "serve-reference-candidate"]

FROM runtime AS controller
CMD ["controlgraph-canary", "serve"]
