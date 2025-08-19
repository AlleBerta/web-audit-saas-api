from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import sqlite3
import os
import time
import json
from datetime import datetime
from scraper import perform_scan # Importa la tua nuova funzione di scraping


app = Flask(__name__)
CORS(app, origins=["http://localhost:4000"])

DATABASE = 'scansioni.db'
OUTPUT_DIR = 'outputs'

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
    output_path = os.path.join(OUTPUT_DIR, output_filename)

    # Assicurati che la directory esista
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=4, ensure_ascii=False)

    print(f"Risultati salvati in: {output_path}")
    
    # Restituiamo lo stato e il percorso per l'aggiornamento del DB
    return status, output_path

@app.route('/start-scan', methods=['POST', 'OPTIONS'])
def start_scan():
    if request.method == "OPTIONS":
        return '', 200  # Risposta vuota ma accettata per il preflight

    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL mancante'}), 400

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

    output_filename = f'project0_scan{scan_id}_{int(time.time())}.json'
    output_path = os.path.join(OUTPUT_DIR, output_filename)

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

if __name__ == '__main__':
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    app.run(debug=True, host='0.0.0.0')
