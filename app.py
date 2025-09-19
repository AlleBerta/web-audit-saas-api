from flask import Flask, request, jsonify, send_file
import requests
from urllib.parse import urlparse
from flask_cors import CORS
import sqlite3
import os
import time
import json
from datetime import datetime
from scraper import perform_scan # Importa la tua nuova funzione di scraping


app = Flask(__name__)
# CORS(app, origins=["http://localhost:4000"]) # Permette CORS per il frontend
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:4000"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

DATABASE = 'scansioni.db'
OUTPUT_DIR = 'outputs'
DIR_SCAN = os.path.join(OUTPUT_DIR, 'scans')
DIR_TEST = os.path.join(OUTPUT_DIR, 'tests')
DIR_RESULT = os.path.join(OUTPUT_DIR, 'results')

# Crea le cartelle se non esistono
for d in [OUTPUT_DIR, DIR_SCAN, DIR_TEST, DIR_RESULT]:
    if not os.path.exists(d):
        os.makedirs(d)


# Per il debug delle richieste in arrivo
# @app.before_request
# def log_request():
#      # Salviamo l'output in un file JSON.
#     output_filename = f'debug.txt'
#     output_path = os.path.join(OUTPUT_DIR, output_filename)

#     # Assicurati che la directory esista
#     if not os.path.exists(OUTPUT_DIR):
#         os.makedirs(OUTPUT_DIR)

#     with open(output_path, 'w', encoding='utf-8') as f:
#         json.dump((f"Metodo: {request.method}, Path: {request.path}, Headers: {dict(request.headers)}"), f, indent=4, ensure_ascii=False)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn
    
def execute_and_save_scan(url, scan_id):
    """
    Funzione esterna che esegue la scansione, gestisce gli errori
    e salva il risultato in un file JSON.
    Restituisce lo stato finale ('done' o 'failed') e il percorso del file.
    """
    print(f"Avvio scansione per l'URL: {url}")
    try:
        print(f"execute and save scan({url},{scan_id}) ... ")
        # Eseguo la funzione perform_scan dal file scraper.py.
        scan_results = perform_scan(url)
        
        status = 'done'
        
        # Creiamo un dizionario finale da salvare nel file JSON
        output_data = {
            'idScan': scan_id,
            'scanTimestamp': str(datetime.now()),
            'scanResults': scan_results # Includiamo i risultati
        }

    except Exception as e:
        # Se lo scraper fallisce, gestiamo l'errore
        print(f"Errore durante la scansione: {e}")
        status = 'failed'
        output_data = {'idScan': scan_id, 'error': str(e)}

    # Salviamo l'output in un file JSON.
    output_filename = f'scan_result_{scan_id}.json'
    output_path = os.path.join((DIR_RESULT), output_filename)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=4, ensure_ascii=False)

    print(f"Risultati salvati in: {output_path}")
    
    # Restituiamo lo stato e il percorso per l'aggiornamento del DB
    return status, output_path


def normalize_url(url: str) -> str:
    # Aggiungi schema se manca
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"URL non valido: {url}")

    print(f"Verifico raggiungibilità di {url} ...")
    # Secondo tentativo: forzare www.
    if not parsed.netloc.startswith("www."):
        url_www = f"{parsed.scheme}://www.{parsed.netloc}{parsed.path or ''}"
        print(f"Provo con {url_www} ...")
        try:
            requests.head(url_www, timeout=3, verify=True)
            return url_www
        except Exception:
            pass

    # Primo tentativo: URL così com'è
    try:
        requests.head(url, timeout=3, verify=True)
        return url
    except requests.exceptions.SSLError:
        print(f"⚠️ Problema SSL con {url}, provo con www.")
    except requests.exceptions.RequestException:
        print(f"⚠️ {url} non raggiungibile, provo con www.")

    raise ValueError(f"Impossibile raggiungere {url}")

@app.route('/start-scan', methods=['POST', 'OPTIONS'])
def start_scan():
    if request.method == "OPTIONS":
        return '', 200  # Risposta vuota ma accettata per il preflight

    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL mancante'}), 400

    try:
        url = normalize_url(url)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    print(f"Normalized URL: {url}")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO scansioni (url, status) VALUES (?, ?)', (url, 'processing'))
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()

    # Scraping web url
    status, output_path = execute_and_save_scan(url, scan_id)
    
    
    output_data = {
        'idScan': scan_id,
        'url': url,
        'result': f'Finta scansione completata per {url} con stato {status} e path {output_path}',
        'timestamp': str(datetime.now())
    }

    output_filename = f'scan{scan_id}_{int(time.time())}.json'
    output_path = os.path.join(DIR_SCAN, output_filename)

    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=4)

    # Aggiorna lo stato nel DB
    conn = get_db_connection()
    conn.execute('''
        UPDATE scansioni
        SET status = ?, pathOutput = ?, timestampEnd = ?
        WHERE idScan = ?
    ''', ('done', output_path, datetime.now(), scan_id))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Scansione avviata', 'idScan': scan_id})

@app.route('/scan-status/<int:scan_id>', methods=['GET'])
def scan_status(scan_id):
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scansioni WHERE idScan = ?', (scan_id,)).fetchone()
    conn.close()

    if scan is None:
        return jsonify({'error': 'Scan ID non trovato'}), 404

    return jsonify({
        'idScan': scan['idScan'],
        'url': scan['url'],
        'status': scan['status'],
        'timestampStart': scan['timestampStart'],
        'timestampEnd': scan['timestampEnd'],
    })

@app.route('/result/<int:scan_id>', methods=['GET'])
def get_result(scan_id):
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scansioni WHERE idScan = ?', (scan_id,)).fetchone()
    conn.close()

    if scan is None:
        return jsonify({'error': 'Scan ID non trovato'}), 404

    if scan['status'] != 'done':
        return jsonify({'error': 'Scansione non completata'}), 400

    if not scan['pathOutput'] or not os.path.exists(scan['pathOutput']):
        return jsonify({'error': 'File risultato non trovato'}), 404

    return send_file(scan['pathOutput'], mimetype='application/json')

# Funzione di test per eseguire una scansione direttamente, non tramite API
def test_scan(url: str):

    try:
        url = normalize_url(url)
    except ValueError as e:
        print(f"❌ Errore URL: {e}")
        exit(1)

    # Inserisci nel DB
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO scansioni (url, status) VALUES (?, ?)', (url, 'processing'))
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()

    print(f"execute_and_save_scan({url},{scan_id})...")
    # Esegui la scansione vera
    status, output_path = execute_and_save_scan(url, scan_id)

    output_data = {
        'idScan': scan_id,
        'url': url,
        'result': f'Finta scansione completata per {url} con stato {status} e path {output_path}',
        'timestamp': str(datetime.now())
    }

    output_filename = f'test_scan{scan_id}_{int(time.time())}.json'
    output_path = os.path.join(DIR_TEST, output_filename)

    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=4)

    # Aggiorna lo stato nel DB
    conn = get_db_connection()
    conn.execute('''
        UPDATE scansioni
        SET status = ?, pathOutput = ?, timestampEnd = ?
        WHERE idScan = ?
    ''', ('done', output_path, datetime.now(), scan_id))
    conn.commit()
    conn.close()

    return output_data



if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", help="Esegui direttamente uno scan", metavar="URL")
    args = parser.parse_args()

    if args.test:
        print(f"▶ Avvio test scan su: {args.test}")
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
        print("----- Inizio Test Scan -----")
        result = test_scan(args.test)
        print("=== Risultato ===")
        print(result)
    else:
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
        app.run(debug=True, host="0.0.0.0", port=5000)

