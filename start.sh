#!/bin/bash
# Copy initial knowledge.db to persistent disk if not exists
if [ -d "/data" ] && [ ! -f "/data/knowledge.db" ] && [ -f "/app/knowledge.db" ]; then
    echo "Copying initial knowledge.db to /data/knowledge.db"
    cp /app/knowledge.db /data/knowledge.db
fi
exec python web_ui.py
