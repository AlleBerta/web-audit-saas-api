#!/bin/bash

# === CONFIGURAZIONE ===
PROJECT_DIR="/home/alleberta/flask-scan"
VENV_DIR="$PROJECT_DIR/venv"
LOG_FILE="$PROJECT_DIR/log.txt"
FLASK_APP="app.py"

# === FUNZIONI ===

start_flask() {
    echo "🟢 Avvio server Flask..."
    cd "$PROJECT_DIR" || exit 1
    source "$VENV_DIR/bin/activate"
    export FLASK_APP=$FLASK_APP
    echo "----- Avvio server: $(date) -----" >> "$LOG_FILE"
    nohup flask run --host=0.0.0.0 >> "$LOG_FILE" 2>&1 &
    echo "✅ Server Flask avviato (in background)."
}

stop_flask() {
    echo "🔴 Fermando il server Flask..."
    PIDS=$(ps aux | grep "[f]lask run" | awk '{print $2}')
    if [ -z "$PIDS" ]; then
        echo "⚠️  Nessun processo Flask trovato."
    else
        echo "$PIDS" | xargs kill
        echo "✅ Server Flask fermato."
    fi
}

restart_flask() {
    stop_flask
    sleep 1
    start_flask
}

# === MAIN ===

# === Use Cases ===
# ./flask.sh start
# ./flask.sh stop
# ./flask.sh restart

case "$1" in
    start)
        start_flask
        ;;
    stop)
        stop_flask
        ;;
    restart)
        restart_flask
        ;;
    *)
        echo "❓ Utilizzo: $0 {start|stop|restart}"
        exit 1
        ;;
esac
