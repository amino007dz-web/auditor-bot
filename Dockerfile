FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python -c "import solcx; solcx.install_solc('0.8.25')" && \
    mkdir -p /data && \
    useradd -m -u 1000 auditoruser && \
    chown -R auditoruser:auditoruser /app /data && \
    chmod +x start.sh

ENV PYTHONUNBUFFERED=1
ENV PORT=5000

USER auditoruser
EXPOSE 5000

CMD ["./start.sh"]
