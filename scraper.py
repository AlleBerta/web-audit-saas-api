import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import socket
import nmap # <-- Importa la libreria nmap
from search_vuln import search_cves, API_KEY # <-- Importa la funzione di ricerca vulnerabilità e la API_KEY

# --- NUOVA FUNZIONE PER LA SCANSIONE DI RETE ---
def scan_network_infrastructure(url):
    """
    Esegue la scansione delle porte e dei servizi sull'host target.
    """
    network_results = {}
    try:
        # 1. Risolvi il dominio in un indirizzo IP
        hostname = urlparse(url).netloc
        ip_address = socket.gethostbyname(hostname)
        network_results['ip_address'] = ip_address

        # 2. Inizializza e avvia la scansione Nmap
        print(f"Avvio scansione Nmap su {ip_address}...")
        nm = nmap.PortScanner()
        # Argomenti: -sV per rilevare la versione, -T4 per una scansione più veloce (ma più "rumorosa"), --top-ports 1000 per le porte più comuni
        # argomenti fast scan = "-sV -T4 --top-ports 1000 -Pn" -Pn per non fare ping
        # argomenti scan più accurata = "-sS -sV -A -p 1-65535 -T4 -Pn" # -sS per SYN scan, -A per rilevamento OS e versioni, -p 1-65535 per tutte le porte
        # Scansioniamo le porte più comuni per velocità
        nm.scan(ip_address, arguments='-sV -T4 --top-ports 1000')
        print('Salvo nm in un file di testo nm.txt')
    
        open_ports = []
        if ip_address in nm.all_hosts():
            host_data = nm[ip_address]
            for proto in host_data.all_protocols():
                ports = host_data[proto].keys()
                for port in sorted(ports):
                    service_info = host_data[proto][port]
                    if service_info['state'] == 'open':
                        port_details = {
                            'port': port,
                            'protocol': proto,
                            'service': service_info.get('name', 'sconosciuto'),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'vulnerabilities': [] # Placeholder per le vulnerabilità
                        }
                        
                        # --- PUNTO DI INTEGRAZIONE PER LA RICERCA CVE ---
                        # Se abbiamo prodotto e versione, possiamo cercare le vulnerabilità
                        if port_details['product'] and port_details['version']:
                            print(f"\n[!] Ricerca CVE per {port_details['product']} {port_details['version']}...\n")

                            # Usiamo direttamente la funzione di search_vuln.py
                            vulns = search_cves(
                                vendor=port_details['product'],  # 🔹 Qui puoi aggiustare se serve vendor reale
                                product=port_details['product'],
                                version=port_details['version'],
                                api_key=API_KEY
                            )

                            # Salvo i risultati normalizzati dentro la struttura della porta
                            port_details['vulnerabilities'] = vulns

                            print(f"[+] Trovate {len(vulns)} vulnerabilità per {port_details['product']} {port_details['version']}.\n")
                        
                        open_ports.append(port_details)
        
        network_results['open_ports'] = open_ports
        print("Scansione Nmap completata.")

    except socket.gaierror:
        network_results['error'] = f"Impossibile risolvere il dominio: {hostname}"
    except Exception as e:
        network_results['error'] = f"Errore durante la scansione Nmap: {e}"

    return network_results

def perform_scan(url):
    """
    Esegue una scansione web di base su un URL e restituisce i risultati in un dizionario.
    """
    scan_results = {
        'url': url,
        'info': {},
        'security_headers': {},
        'robots_txt': {},
        'terms_of_service': {'found': False, 'link': None},
        'custom_data': {}, # Per i dati specifici che vuoi estrarre
        'network_scan': {} # Per i risultati della scansione di rete
    }
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    # === ESEGUI LA SCANSIONE DI RETE PRIMA DI TUTTO ===
    scan_results['network_scan'] = scan_network_infrastructure(url)

    try:
        # 1. Richiesta principale e informazioni base
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status() # Lancia un errore per status code 4xx/5xx
        
        scan_results['info']['status_code'] = f"{response.status_code} {response.reason}"
        scan_results['info']['server'] = response.headers.get('Server', 'Non specificato')

        # 2. Controllo metodi HTTP abilitati (con OPTIONS)
        try:
            options_response = requests.options(url, headers=headers, timeout=5)
            scan_results['info']['allowed_methods'] = options_response.headers.get('Allow', 'Non specificato (OPTIONS non supportato)')
        except requests.exceptions.RequestException:
            scan_results['info']['allowed_methods'] = 'Errore durante la richiesta OPTIONS'

        # 3. Controllo header di sicurezza comuni
        security_headers_to_check = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options'
        ]
        for header in security_headers_to_check:
            scan_results['security_headers'][header] = response.headers.get(header, 'Mancante')

        # 4. Analisi HTML con BeautifulSoup
        if 'text/html' in response.headers.get('Content-Type', ''):
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Controllo directory listing
            title = soup.find('title')
            if title and 'index of' in title.text.lower():
                scan_results['info']['directory_listing_warning'] = True
            
            # Cerca link a "Termini di Servizio"
            terms_link = soup.find('a', text=re.compile(r'termini|terms|privacy', re.IGNORECASE))
            if terms_link and terms_link.has_attr('href'):
                scan_results['terms_of_service']['found'] = True
                scan_results['terms_of_service']['link'] = urljoin(url, terms_link['href'])
            
            # --- SEZIONE DA PERSONALIZZARE ---
            # Qui puoi inserire i tuoi selettori per estrarre dati specifici.
            # Esempio: estrarre tutti i titoli h1
            h1_tags = [h1.get_text(strip=True) for h1 in soup.select('h1')]
            scan_results['custom_data']['h1_titles'] = h1_tags
            # ---------------------------------

        # 5. Controllo robots.txt
        robots_url = urljoin(url, '/robots.txt')
        try:
            robots_response = requests.get(robots_url, headers=headers, timeout=5)
            if robots_response.status_code == 200:
                scan_results['robots_txt']['found'] = True
                scan_results['robots_txt']['content'] = robots_response.text
            else:
                scan_results['robots_txt']['found'] = False
        except requests.exceptions.RequestException:
            scan_results['robots_txt']['found'] = False
            scan_results['robots_txt']['error'] = 'Impossibile raggiungere robots.txt'

    except requests.exceptions.RequestException as e:
        scan_results['error'] = f"Errore durante la richiesta a {url}: {e}"

    return scan_results
