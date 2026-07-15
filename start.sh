#!/bin/bash

# Copy initial knowledge.db to persistent disk if not exists
if [ -d "/data" ] && [ ! -f "/data/knowledge.db" ] && [ -f "/app/knowledge.db" ]; then
    echo "Copying initial knowledge.db to /data/knowledge.db"
    cp /app/knowledge.db /data/knowledge.db
fi

# Pre-install solc for gas profiling (background, non-blocking)
echo "Pre-installing solc 0.8.25 for gas profiler..."
python -c "import solcx; solcx.install_solc('0.8.25', silent=True)" 2>&1 | tail -1 &

exec python web_ui.py
