#!/bin/bash
set -e

if [ -d "/data" ] && [ ! -f "/data/knowledge.db" ] && [ -f "/app/knowledge.db" ]; then
    echo "Copying initial knowledge.db to /data/knowledge.db"
    cp /app/knowledge.db /data/knowledge.db
fi

exec gunicorn web_ui:app \
    --bind 0.0.0.0:${PORT:-5000} \
    --workers 2 \
    --worker-class gevent \
    --worker-connections 100 \
    --timeout 120 \
    --graceful-timeout 30 \
    --access-logfile - \
    --error-logfile -
