# One image for both roles: the harness (`cdr-cts run`) and the mock ecosystem (`cdr-cts mock`).
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY scenarios ./scenarios
RUN pip install ".[mock]" \
 && useradd --create-home --uid 10001 cts \
 && mkdir -p /work/out /work/keys \
 && chown -R cts:cts /work

USER cts
WORKDIR /work
ENTRYPOINT ["cdr-cts"]
CMD ["list"]
