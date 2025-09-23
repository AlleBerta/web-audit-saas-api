#!/bin/bash

# === CONFIGURAZIONE ===
PROJECT_DIR="/home/alleberta/flask-scan"
VENV_DIR="$PROJECT_DIR/venv"
LOG_FILE="$PROJECT_DIR/log.txt"             # log api    
TEST_LOG_FILE="$PROJECT_DIR/test_log.txt"   # log test
FLASK_APP="app.py"

# === FUNZIONI ===

get_ip() {
    hostname -I | awk '{print $1}'
}

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

test_flask() {
    echo "🧪 Avvio test scan..."
    cd "$PROJECT_DIR" || exit 1
    source "$VENV_DIR/bin/activate"
    echo "----- Test scan: $(date) -----" >> "$TEST_LOG_FILE"
    python app.py --test "https://corsineosin.mflabs.it" | tee -a "$TEST_LOG_FILE"
}

# http://www.example.com
# http://www.montecchiocalcio.it
# http://marcotrombi.com
# https://sms.pingme.co.in
# https://www.amazon.it
# https://www.backlinko.com
# https://www.scanme.nmap.org


# === MAIN ===

# === Use Cases ===
# ./flask.sh start
# ./flask.sh stop
# ./flask.sh restart
# ./flask.sh test

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
    test) 
        test_flask 
        ;;
    ip)
        get_ip
        ;;
    *) 
        echo "❓ Utilizzo: $0 {start|stop|restart|test}" ; 
        exit 1 ;;
esac
