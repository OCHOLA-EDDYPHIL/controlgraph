FROM python:3.12.13-alpine3.22@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322 AS runtime

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

FROM python:3.12.13-alpine3.22@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322 AS advisor-runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_NO_CACHE=1 \
    PATH="/app/.venv/bin:${PATH}" \
    PORT=8080

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN python -m pip install --no-cache-dir --disable-pip-version-check "uv==0.12.3" \
    && uv sync --frozen --no-dev --extra advisor --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --extra advisor --no-editable \
    && /usr/local/bin/python -m pip uninstall --yes uv

USER 65532:65532
EXPOSE 8080

FROM advisor-runtime AS advisor
CMD ["controlgraph-canary", "serve"]

FROM runtime AS reference-stable
CMD ["controlgraph-canary", "serve-reference-stable"]

FROM runtime AS reference-candidate
CMD ["controlgraph-canary", "serve-reference-candidate"]

FROM runtime AS controller
CMD ["controlgraph-canary", "serve"]
