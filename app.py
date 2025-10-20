from flask import Flask, request, jsonify, send_file
import requests
from urllib.parse import urlparse
from flask_cors import CORS
import mysql.connector
import os
import time
import json
from datetime import datetime
from scraper import perform_scan # Importa la tua nuova funzione di scraping
import threading
from dotenv import load_dotenv
from server_response import server_response # Per eseguire lo scraping in un thread separato, in modo da non bloccare l'API

load_dotenv()  # Carica le variabili d'ambiente dal file .env

app = Flask(__name__)
# CORS(app, origins=["http://localhost:4000"]) # Permette CORS per il frontend
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3001"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

DATABASE = 'scansioni.db'
OUTPUT_DIR = 'outputs'
DIR_TEST = os.path.join(OUTPUT_DIR, 'test_results')
DIR_RESULT = os.path.join(OUTPUT_DIR, 'results')

# Crea le cartelle se non esistono
for d in [OUTPUT_DIR, DIR_TEST, DIR_RESULT]:
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
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=os.getenv("DB_PORT", 3306)
    )
    return conn
    
def failed_scan(scanId: int):
    """
    Funzione per aggiornare lo stato di una scansione fallita nel database.
    """
    if scanId == 0:
        return
    try: 
        conn = get_db_connection()
        cur = conn.cursor()
        conn.execute(
            'UPDATE scans SET state = %s, end_time = %s, updatedAt = NOW() WHERE id = %s',
            ('failed', datetime.now(), scanId)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        server_response(500, False, f"Errore durante l'aggiornamento del database: {e}")


# def execute_and_save_scan(url: str, scanId: int, isTest: bool = False):
#     """
#     Funzione esterna che esegue la scansione, gestisce gli errori
#     e salva il risultato in un file JSON.
#     Restituisce lo stato finale ('done' o 'failed') e il percorso del file.
#     """
#     print(f"Avvio scansione per l'URL: {url}")
#     try:
#         print(f"execute and save scan({url},{scanId}) ... ")
#         # Eseguo la funzione perform_scan dal file scraper.py.
#         scan_results = perform_scan(url)
        
        
#         # Creiamo un dizionario finale da salvare nel file JSON
#         output_data = {
#             'idScan': scanId,
#             'scanTimestamp': str(datetime.now()),
#             'scanResults': scan_results # Includiamo i risultati
#         }
        
#     except Exception as e:
#         # Se lo scraper fallisce, gestiamo l'errore
#         print(f"Errore durante la scansione: {e}")
#         status = 'failed'
#         output_data = {'idScan': scanId, 'error': str(e)}

#     # Salviamo l'output in un file JSON.
#     output_filename = f'scan_result_{scanId}.json'
#     if(isTest):
#         output_path = os.path.join((DIR_TEST), output_filename)
#     else:
#         output_path = os.path.join((DIR_RESULT), output_filename)
        

#     with open(output_path, 'w', encoding='utf-8') as f:
#         json.dump(output_data, f, indent=4, ensure_ascii=False)

#     print(f"Risultati salvati in: {output_path}")
    
#     # Aggiorna lo stato nel DB in scans
#     try:
#         conn = get_db_connection()
#         cur = conn.cursor()
#         conn.execute(
#             'UPDATE scans SET state = %s, report_path = %s, end_time = %s, updatedAt = NOW() WHERE id = %s',
#             ('done', output_path, datetime.now(), scanId)
#         )
#         conn.commit()
#         conn.close()
#     except Exception as e:
#         server_response(500, False, f"Errore durante l'aggiornamento del database: {e}")

def execute_and_save_scan(url: str, scanId: int, isTest: bool = False):
    """
    Esegue la scansione, salva il risultato in JSON
    e aggiorna il database (scans, targets, scan_results)
    """
    print(f"Avvio scansione per l'URL: {url}")
    try:
        # Eseguo la funzione perform_scan dal file scraper.py.
        scan_results = perform_scan(url)

        # Costruisco il JSON finale
        output_data = {
            'idScan': scanId,
            'scanTimestamp': str(datetime.now()),
            'scanResults': scan_results
        }

    except Exception as e:
        print(f"Errore durante la scansione: {e}")
        output_data = {'idScan': scanId, 'error': str(e)}
        status = 'failed'
    else:
        status = 'done'

    # Salvataggio su file
    output_filename = f'scan_result_{scanId}.json'
    output_path = os.path.join(DIR_TEST if isTest else DIR_RESULT, output_filename)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=4, ensure_ascii=False)

    print(f"Risultati salvati in: {output_path}")

    # === Aggiornamento DB ===
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        print("Aggiorno anche il db:\nParto da scans")
        # 1. Aggiorna scans
        cur.execute(
            """
            UPDATE scans
            SET state = %s, report_path = %s, end_time = %s, updatedAt = NOW()
            WHERE id = %s
            """,
            (status, output_path, output_data.get("scanTimestamp"), scanId)
        )
        print("Poi aggiorno targets")
        # 2. Aggiorna targets (recupero id_target associato alla scansione)
        cur.execute("SELECT targetId FROM scans WHERE id = %s", (scanId,))
        target_id_row = cur.fetchone()
        if target_id_row:
            target_id = target_id_row[0]
            ip_addr = (
                output_data
                .get("scanResults", {})
                .get("network_scan", {})
                .get("ip_address")
            )
            if ip_addr:
                cur.execute(
                    "UPDATE targets SET ip_domain = %s, updatedAt = NOW() WHERE id = %s", 
                    (ip_addr, target_id)
                )
        print("Poi aggiorno scan_results")
        # 3. Inserisci risultati CVE in scan_results
        cve_list = (
            output_data
            .get("scanResults", {})
            .get("network_scan", {})
            .get("cve_search", [])
        )

        def severity_from_score(score):
            if score < 2.5:
                return "Low"
            elif score < 5:
                return "Medium"
            elif score < 7.5:
                return "High"
            else:
                return "Critical"

        if isinstance(cve_list, list):
            for cve in cve_list:
                cve_id = cve.get("cve_id")
                title = cve.get("title")
                base_score = cve.get("cvss", {}).get("base_score_v3")

                if cve_id and base_score is not None:
                    severity = severity_from_score(base_score)
                    cur.execute(
                        """
                        INSERT INTO scan_results (scanId, vulnerabilityType, severity, description, createdAt, updatedAt)
                        VALUES (%s, %s, %s, %s, NOW(), NOW())
                        """,
                        (scanId, cve_id, severity, title)
                    )

        print("Parte il commit finale")
        # Commit finale
        conn.commit()
        print(f"Dati della scansione {scanId} salvati con successo.")

    except Exception as e:
        print(f"❌ Errore durante l'aggiornamento del database: {e}")
        conn.rollback()

        cur.execute(
            """
            UPDATE scans
            SET state = %s, end_time = %s, updatedAt = NOW()
            WHERE id = %s
            """,
            ('failed', output_data.get("scanTimestamp"), scanId)
        )
        conn.commit()

    finally:
        conn.close()

    print("SCANSIONE TERMIANTA")

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
        print("Headers:", request.headers, flush=True)
        print("Raw body:", request.data, flush=True)
        print("JSON parsed:", data, flush=True)
        return server_response(200, True, "Preflight OK")  # Risposta vuota ma accettata per il preflight

    data = request.get_json()
    print(f"Data Received: {data}")
    url = data.get('url')
    scanId = data.get('scanId') or 0 # Se non fornito, uso 0 come valore di default
    if not url or scanId == 0:
        failed_scan(scanId)
        return server_response(400, False, 'Url o ScanId mancante')
    
    print(f"ricevuta richiesta: {url}, idScan: {scanId}")

    try:
        url = normalize_url(url)
    except ValueError as e:
        return server_response(400, False, str(e))

    print(f"Normalized URL: {url}")

    # Aggiorno il DB: riga con id=scanID con state = 'running', start_time = ora corrente
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'UPDATE scans SET state =%s, start_time =%s, updatedAt = NOW() WHERE id=%s',
        ('running', datetime.now(), scanId)
    )
    conn.commit()
    conn.close()

    # Avvio la scansione in background
    thread = threading.Thread(target=execute_and_save_scan, args=(url, scanId))
    thread.start()

    # Risposta immediata al client
    return server_response(
        200,
        True,
        'Scansione avviata',
        {
            'idScan': scanId, 
            'status': 'processing'
        }
    )
    

# @app.route('/scan-status/<int:scanId>', methods=['GET'])
# def scan_status(scanId):
#     if not scanId:
#         return server_response(400, False, 'ScanId is missing')
    
#     conn = get_db_connection()
#     scan = conn.execute('SELECT * FROM scans WHERE id = ?', (scanId,)).fetchone()
#     conn.close()

#     if scan is None:
#         return server_response(404, False, 'ScanID not founded')

#     return server_response(
#         200,
#         True,
#         '',
#         {
#             'idScan': scan['idScan'],
#             'url': scan['url'],
#             'status': scan['state'],
#             'timestampStart': scan['timestampStart'],
#             'timestampEnd': scan['timestampEnd'],
#         }
#     )

# @app.route('/result/<int:scanId>', methods=['GET'])
# def get_result(scanId):
#     if not scanId:
#         return server_response(400, False, 'ScanId is missing')
    
#     conn = get_db_connection()
#     scan = conn.execute('SELECT * FROM scans WHERE id = ?', (scanId,)).fetchone()
#     conn.close()

#     if scan is None:
#         return server_response(404, False, 'Scan ID not founded')

#     if scan['state'] != 'done':
#         return server_response(400, False, 'Scan not completed')

#     if not scan['pathOutput'] or not os.path.exists(scan['pathOutput']):
#         return server_response(404, False, 'Output File not founded')

#     # leggo il pathOutput
#     with open(scan['pathOutput'], "r", encoding="utf-8") as f:
#         file_data = json.load(f)

#     return server_response(200, True, 'Scansione terminated with success!', file_data)

# Funzione di test per eseguire una scansione direttamente, non tramite API
def test_scan(url: str):

    try:
        url = normalize_url(url)
    except ValueError as e:
        print(f"❌ Errore URL: {e}")
        exit(1)

    targetId = 6  # ID di test
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO scans (targetId, state, startTime, createdAt, updatedAt) VALUES (%s, %s, %s, NOW(), NOW())',
        (targetId, 'processing', datetime.now())
    )
    scanId = cur.lastrowid
    conn.commit()
    conn.close()


    print(f"execute_and_save_scan({url},{scanId})...")

    # Avvio la scansione in background
    thread = threading.Thread(target=execute_and_save_scan, args=(url, scanId, DIR_TEST))
    thread.start()

    # Risposta immediata al client
    return {'status': 200, 'message': 'Scansione avviata', 'data':{'idScan': scanId, 'status': 'processing'}}


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

