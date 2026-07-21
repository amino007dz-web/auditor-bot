#!/bin/bash
set -e

if [ -d "/data" ] && [ ! -f "/data/knowledge.db" ] && [ -f "/app/knowledge.db" ]; then
    echo "Copying initial knowledge.db to /data/knowledge.db"
    cp /app/knowledge.db /data/knowledge.db
fi

exec gunicorn web_ui:app \
    --bind 0.0.0.0:${PORT:-5000} \
    --workers ${WEB_CONCURRENCY:-1} \
    --worker-class gevent \
    --worker-connections 50 \
    --timeout 300 \
    --graceful-timeout 30 \
    --access-logfile - \
    --error-logfile -
