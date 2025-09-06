from dotenv import load_dotenv
import os
import cloudscraper
import requests
import re

# Carico le variabili d'ambiente dal file .env
load_dotenv()
API_KEY = os.getenv("CVEDETAILS_API_KEY")
BASE_URL = os.getenv("BASE_URL","https://www.cvedetails.com") # fallback se non definito


def get_version_id(vendor, product, version):
    """
    Recupera il version_id a partire da vendor, product e version
    usando un redirect controllato.
    """
    scraper = cloudscraper.create_scraper()  # simula un browser con challenge solver

    search_url = f"{BASE_URL}/version-search.php?page=1&vendor={vendor}&product={product}&version={version}"
    print(f"Searching version_id at: {search_url}")

    # Non seguo il redirect per leggere manualmente l'header "Location"
    response = scraper.get(search_url, allow_redirects=False)
    
    if response.status_code != 302:
        raise Exception(f"Errore nella ricerca version_id: {response.status_code}")

    location = response.headers.get("Location")
    if not location:
        raise Exception("Location non trovata nella risposta!")

    # Estrai il version_id dal path
    # Esempio di Location: "/vulnerability-list/vendor_id-00/product_id-00/version_id-0000000/"
    match = re.search(r"version_id-(\d+)", location)
    if not match:
        raise Exception("Impossibile estrarre version_id dall'URL di redirect.")
    
    return match.group(1)

def get_cves_by_version_id(version_id, api_key):
    """
    Recupera tutte le CVE associate a un determinato version_id
    tramite le API ufficiali di CVEDetails.
    """
    if not API_KEY:
        raise ValueError("❌ API Key mancante! Imposta CVEDETAILS_API_KEY nel file .env")

    api_url = f"{BASE_URL}/api/v1/vulnerability/search?versionId={version_id}"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }

    response = requests.get(api_url, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Errore nella chiamata API CVE Details: {response.status_code} - {response.text}")
    
    return response.json()

def normalize_cve_data(item):
    """
    Trasforma un item CVE grezzo in un formato pulito e coerente
    pronto per essere salvato nel database o inviato al frontend.
    """
    # Campi da salvare:
    # | Campo JSON                   | Motivazione                                               |
    # | ---------------------------- | ----------------------------------------------------------|
    # | `cveId` (`CVE-2025-53020`)   | Identificativo univoco della vulnerabilità                |
    # | `title`                      | Nome leggibile della vulnerabilità                        |
    # | `summary`                    | Descrizione breve, utile in dashboard o report            |
    # | `publishDate`                | Data di pubblicazione (per capire quanto è recente)       |
    # | `updateDate`                 | Ultimo aggiornamento (se la CVE è stata rivista)          |
    # | `maxCvssBaseScorev3`         | Gravità secondo **CVSS v3**, standard attuale             |
    # | `maxCvssImpactScore`         | Impatto potenziale (utile per classificare)               |
    # | `maxCvssExploitabilityScore` | Quanto è sfruttabile la vulnerabilità                     |
    # | `epssScore`                  | Probabilità di sfruttamento reale, utile per la priorità  |
    # | `product` + `version_title`  | Sapere a cosa si riferisce (es. Apache HTTP 2.4.59)       |
    # | `vendor` + `vendor_id`       | Per filtrare in futuro per vendor                         |
    # | `product_id` + `version_id`  | Collegamento ai sistemi interni di CVEDetails             |
    # | `full_cpe_str`               | Stringa standardizzata per identificare un software (CPE) |
    # | `exploitExists`              | Flag se esiste già un exploit pubblico                    |
    # | `referenceCount`             | Numero di riferimenti alla CVE                            |
    # | `weaknessCount`              | Numero di debolezze collegate                             |
    # | `nvdVulnStatus`              | Stato nella NVD (es. Analyzed, Awaiting Analysis)         |
    # | `isOverflow`                 | Tipo di vulnerabilità (buffer overflow)                   |
    # | `isMemoryCorruption`         | Tipo di vulnerabilità (memory corruption)                 |
    # | `isSqlInjection`             | Tipo di vulnerabilità (SQL Injection)                     |
    # | `isXss`                      | Tipo di vulnerabilità (Cross-Site Scripting)              |
    # | `isDirectoryTraversal`       | Tipo di vulnerabilità (Directory Traversal)               |
    # | `isFileInclusion`            | Tipo di vulnerabilità (File Inclusion)                    |
    # | `isCsrf`                     | Tipo di vulnerabilità (CSRF)                              |
    # | `isXxe`                      | Tipo di vulnerabilità (XXE)                               |
    # | `isSsrf`                     | Tipo di vulnerabilità (SSRF)                              |
    # | `isOpenRedirect`             | Tipo di vulnerabilità (Open Redirect)                     |
    # | `isInputValidation`          | Tipo di vulnerabilità (Input Validation)                  |
    # | `isCodeExecution`            | Tipo di vulnerabilità (Code Execution)                    |
    # | `isBypassSomething`          | Tipo di vulnerabilità (Bypass Something)                  |
    # | `isGainPrivilege`            | Tipo di vulnerabilità (Gain Privilege)                    |
    # | `isDenialOfService`          | Tipo di vulnerabilità (Denial of Service)                 |
    # | `isInformationLeak`          | Tipo di vulnerabilità (Information Leak)                  |
    # | `isUsedForRansomware`        | Tipo di vulnerabilità (Used For Ransomware)               |

    return {
        # Identificativo CVE
        "cve_id": item.get("cveId"),
        "title": item.get("title"),
        "summary": item.get("summary"),

        # Informazioni sul prodotto e versione
        "vendor": {
            "id": item.get("vendor_id"),
            "name": item.get("vendor")
        },
        "product": {
            "id": item.get("product_id"),
            "name": item.get("product"),
            "version_id": item.get("version_id"),
            "version_title": item.get("version_title"),
            "cpe": item.get("full_cpe_str"),
        },

        # Date
        "publish_date": item.get("publishDate"),
        "update_date": item.get("updateDate"),

        # CVSS (metriche di severità)
        "cvss": {
            "base_score_v3": safe_float(item.get("maxCvssBaseScorev3")),
            "impact_score": safe_float(item.get("maxCvssImpactScore")),
            "exploitability_score": safe_float(item.get("maxCvssExploitabilityScore")),
        },

        # EPSS (probabilità di sfruttamento reale)
        "epss": {
            "score": safe_float(item.get("epssScore")),
            "percentile": safe_float(item.get("epssPercentile")),
        },

        # Informazioni extra
        "exploit_exists": item.get("exploitExists") == "1",
        "reference_count": int(item.get("referenceCount", 0)),
        "weakness_count": int(item.get("weaknessCount", 0)),
        "nvd_status": item.get("nvdVulnStatus"),

        # Tipologia di vulnerabilità (flags)
        "flags": {
            "overflow": item.get("isOverflow") == "1",
            "memory_corruption": item.get("isMemoryCorruption") == "1",
            "sql_injection": item.get("isSqlInjection") == "1",
            "xss": item.get("isXss") == "1",
            "directory_traversal": item.get("isDirectoryTraversal") == "1",
            "file_inclusion": item.get("isFileInclusion") == "1",
            "csrf": item.get("isCsrf") == "1",
            "xxe": item.get("isXxe") == "1",
            "ssrf": item.get("isSsrf") == "1",
            "open_redirect": item.get("isOpenRedirect") == "1",
            "input_validation": item.get("isInputValidation") == "1",
            "code_execution": item.get("isCodeExecution") == "1",
            "bypass": item.get("isBypassSomething") == "1",
            "privilege_escalation": item.get("isGainPrivilege") == "1",
            "dos": item.get("isDenialOfService") == "1",
            "information_leak": item.get("isInformationLeak") == "1",
            "ransomware": item.get("isUsedForRansomware") == "1",
        },

        # URL alla pagina della CVE su CVEDetails
        "url": f"https://www.cvedetails.com/cve/{item.get('cveId')}/",
    }

def safe_float(value):
    """Converte una stringa in float in sicurezza, ritorna None se non valido."""
    try:
        return float(value) if value is not None and value != "" else None
    except ValueError:
        return None

def search_cves(vendor, product, version, api_key):
    """
    Flusso completo:
    1. Trova il version_id tramite redirect
    2. Recupera la lista CVE con le API
    3. Normalizza i dati per il database/frontend
    """
    try:
        print(f"[*] Cerco version_id per {vendor} {product} {version}...")
        version_id = get_version_id(vendor, product, version)
        print(f"[+] Trovato version_id: {version_id}")

        print("[*] Recupero CVE associate a questa verione...")
        raw_data = get_cves_by_version_id(version_id, api_key)
        
        results = raw_data.get("results", [])
        print(f"[+] Trovate {len(results)} CVE")

        # Normalizzo e ritorno solo i dati puliti
        return [normalize_cve_data(item) for item in results]

    except Exception as e:
        print(f"Errore: {e}")
        return []

# API_KEY = "a255c57b3672d4b90a454442bf7c3e65c790ec3c.eyJzdWIiOjE0MDkxLCJpYXQiOjE3NTcwNjU1MDEsImV4cCI6MTc2NzEzOTIwMCwia2lkIjoxLCJjIjoibGw3VGJtNGtcL0hISmpBN1wvK1wvS0RsdmlSUmJMeG0rTnNLbEZkdCtVMVJENEdYeGxGRTE4VjRyREZKYXhiNnZ5K3lSdlk2b2JYRlE9PSJ9"

# vendor = "Apache"
# product = "http"
# version = "2.4.59"

# results = search_cves(vendor, product, version, API_KEY)

# for vuln in results[:5]:
#     print(f"{vuln['cve_id']} - {vuln['summary']} \n(Score EPSS: {vuln['epss']['score']})\t (Score CVSSv3: {vuln['cvss']['base_score_v3']})")
#     print(f"Link: {vuln['url']}\n")
