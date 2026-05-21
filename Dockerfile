FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY README.md ./
RUN pip install --no-cache-dir ".[fastapi]"

HEALTHCHECK --interval=30s --timeout=10s --retries=2 \
    CMD python -c "from secguard import scan_value, scan_text; print('ok')" || exit 1

ENTRYPOINT ["secguard-scan"]
CMD ["--help"]
