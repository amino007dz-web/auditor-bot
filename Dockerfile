# ── Stage 1: Build ────────────────────────────────────────────
FROM python:3.10-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

COPY . .

# ── Stage 2: Runtime ─────────────────────────────────────────
FROM python:3.10-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/root/.local/bin:$PATH"
ENV PYTHONIOENCODING=utf-8
ENV KB_USE_ST=0
ENV API_PROVIDER=ollama
ENV OLLAMA_BASE_URL=https://ollama.com
ENV OLLAMA_MODEL=qwen3-coder:480b
# OLLAMA_API_KEY must be set via Render dashboard (secret)

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local
COPY --from=builder /build .

RUN mkdir -p reports

EXPOSE 5000

RUN chmod +x /app/start.sh
CMD ["/app/start.sh"]
