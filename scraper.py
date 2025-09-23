import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import socket
import nmap # <-- Importa la libreria nmap
from search_vuln import search_cves, API_KEY # <-- Importa la funzione di ricerca vulnerabilità e la API_KEY
# Per il parsing XML (sitemap)
import xml.etree.ElementTree as ET
import gzip, io, time

COMMON_SITEMAP_PATHS = [
    '/sitemap.xml',
    '/sitemap_index.xml',
    '/sitemap/sitemap.xml',
    '/sitemap-index.xml',
    '/sitemap1.xml',
    '/sitemap.xml.gz',
]

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

def parse_sitemap_xml(text):
    urls = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return urls
    def strip_ns(tag): return tag.split('}')[-1].lower()
    if strip_ns(root.tag) == 'sitemapindex':
        for sm in root.findall('.//{*}sitemap'):
            loc = sm.find('{*}loc')
            if loc is not None and loc.text:
                urls.append(loc.text.strip())
    else:
        for u in root.findall('.//{*}url'):
            loc = u.find('{*}loc')
            if loc is not None and loc.text:
                urls.append(loc.text.strip())
    return urls

def fetch_sitemap(url_sitemap):
    try:
        r = requests.get(url_sitemap, headers=headers, timeout=8)
        r.raise_for_status()
        content = r.content
        # gestisci gz
        if url_sitemap.endswith('.gz') or content[:2] == b'\x1f\x8b':
            buf = io.BytesIO(content)
            with gzip.GzipFile(fileobj=buf) as gz:
                text = gz.read().decode('utf-8', errors='ignore')
        else:
            text = r.text
        return parse_sitemap_xml(text)
    except Exception:
        return []
    


# --- NUOVA FUNZIONE PER LA SCANSIONE DI RETE ---
def scan_network_infrastructure(url, http_headers=None):
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
        founded_ports = []
        if ip_address in nm.all_hosts():
            host_data = nm[ip_address]
            print(f"Host {ip_address} ({host_data.hostname()}) - Stato: {host_data.state()}")
            for proto in host_data.all_protocols():
                # Creo tre variabili per tenere traccia di service, product e version
                vendor = product = version = None
                for port in sorted(host_data[proto].keys()):
                    service_info = host_data[proto][port]
                    print(f"Porta {port}/{proto} - Stato: {service_info['state']} - Servizio: {service_info.get('name', 'sconosciuto')} - Versione: {service_info.get('version', 'sconosciuta')}")
                    
                    port_details = {
                        'port': port,
                        'protocol': proto,
                        'state': service_info['state'],
                        'service': service_info.get('name', 'sconosciuto'),     # es: httpd
                        'vendor': service_info.get('vendor', ''),               # es: Apache
                        'product': service_info.get('product', ''),             # es: Apache httpd
                        'version': service_info.get('version', '')              # es: 2.4.41
                    }

                    founded_ports.append(port_details)
                    network_results['open_ports'] = founded_ports

                    # Se il servizio è aperto, procediamo con la ricerca di vendor, product e version
                    if service_info['state'] == 'open':
                        
                        vendor = service_info.get('vendor', None)
                        product = service_info.get('product', None)
                        version = service_info.get('version', None)

                        print(f"Dettagli servizio: {port_details}")
            
            # Finito di iterare sulle porte, procediamo con la ricerca CVE se abbiamo vendor e version
            if not vendor or not version:
                # Proviamo a dedurli dal nome del servizio
                print(http_headers)
            # --- PUNTO DI INTEGRAZIONE PER LA RICERCA CVE ---
            print(f"\n[!] Ricerca CVE per {port_details['vendor']}, {port_details['product']} v{port_details['version']}...\n")

            # Usiamo direttamente la funzione di search_vuln.py
            vulns = search_cves(
                vendor=vendor,  
                product=product,
                version=version,
                api_key=API_KEY
            )

            # Salvo i risultati normalizzati dentro la struttura della porta
            network_results['cve_search'] = vulns

            print(f"[+] Trovate {len(vulns)} vulnerabilità per {port_details['product']} {port_details['version']}.\n")
            
        print("Scansione Nmap completata.")

    except socket.gaierror:
        network_results['error'] = f"Impossibile risolvere il dominio: {hostname}"
    except Exception as e:
        network_results['error'] = f"Errore durante la scansione Nmap: {e}"

    # print(f"network_results: {network_results}")
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
        'sitemap': {},
        'terms_of_service': {'found': False, 'link': None},
        'custom_data': {}, # Per i dati specifici che vuoi estrarre
        'network_scan': {} # Per i risultati della scansione di rete
    }

    try:
        # 1. Richiesta principale e informazioni base
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status() # Lancia un errore per status code 4xx/5xx
        
        scan_results['info']['status_code'] = f"{response.status_code} {response.reason}"
        scan_results['info']['server'] = response.headers.get('Server', 'Non specificato')

        # 2. Controllo metodi HTTP abilitati (con OPTIONS)
        try:
            options_response = requests.options(url, headers=headers, timeout=5)
            print(f"OPTIONS response headers: {options_response.headers}")
            scan_results['info']['allowed_methods'] = options_response.headers.get('Allow', 'Non specificato (OPTIONS non supportato)')
        except requests.exceptions.RequestException:
            scan_results['info']['allowed_methods'] = 'Errore durante la richiesta OPTIONS'

        print(f"scan_network_infrastructure({url}) ... ")
        # 3. Eseguo la scansione di rete, trovo il server HTTP se presente e restituisco i risultati con eventuale ricerca CVE associata al server
        scan_results['network_scan'] = scan_network_infrastructure(url, http_headers=response.headers['Server'] if 'Server' in response.headers else None)

        # 4. Controllo header di sicurezza comuni
        security_headers_to_check = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options'
        ]
        for header in security_headers_to_check:
            scan_results['security_headers'][header] = response.headers.get(header, 'Mancante')

        # 5. Analisi HTML con BeautifulSoup
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

        # 6. Controllo robots.txt
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



        # 7. Tentativo di trovare sitemap.xml
        # Assumi root già calcolato: root = f"{parsed.scheme}://{parsed.netloc}"
        parsed = urlparse(url)
        root = f"{parsed.scheme}://{parsed.netloc}"

        found_sitemaps = []
        sitemap_urls_map = {}

        # 1) Se robots_response esiste ed è 200, abbiamo già controllato robots.txt sopra:
        if 'robots_response' in locals() and robots_response is not None and robots_response.status_code == 200:
            for line in robots_response.text.splitlines():
                if line.strip().lower().startswith('sitemap:'):
                    loc = line.split(':', 1)[1].strip()
                    loc = urljoin(root, loc)
                    if loc not in found_sitemaps:
                        found_sitemaps.append(loc)
                        sitemap_urls_map[loc] = fetch_sitemap(loc)
                        time.sleep(0.2) # breve pausa per non sovraccaricare

        # 2) Prova percorsi comuni
        for p in COMMON_SITEMAP_PATHS:
            candidate = urljoin(root, p)
            if candidate in found_sitemaps:
                continue
            try:
                head = requests.head(candidate, headers=headers, timeout=5, allow_redirects=True)
                if head.status_code in (200,301,302) or 'xml' in head.headers.get('Content-Type',''):
                    urls = fetch_sitemap(candidate)
                    if urls:
                        found_sitemaps.append(candidate)
                        sitemap_urls_map[candidate] = urls
                time.sleep(0.2)
            except Exception:
                # fallback: prova GET diretto
                urls = fetch_sitemap(candidate)
                if urls:
                    found_sitemaps.append(candidate)
                    sitemap_urls_map[candidate] = urls
                time.sleep(0.2)
        
        # 3) Scansiona la homepage per link a sitemap
        try:
            homepage_resp = requests.get(root, headers=headers, timeout=6)
            if homepage_resp.status_code == 200 and 'text/html' in homepage_resp.headers.get('Content-Type',''):
                soup_root = BeautifulSoup(homepage_resp.text, 'html.parser')
                # <link rel="sitemap" href="...">
                for link in soup_root.find_all('link', href=True):
                    if 'sitemap' in link.get('href','').lower():
                        loc = urljoin(root, link['href'])
                        if loc not in found_sitemaps:
                            urls = fetch_sitemap(loc)
                            if urls:
                                found_sitemaps.append(loc)
                                sitemap_urls_map[loc] = urls
                                time.sleep(0.2)
                # <a href> con sitemap
                for a in soup_root.find_all('a', href=True):
                    if 'sitemap' in a['href'].lower() or 'sitemap.xml' in a['href'].lower():
                        loc = urljoin(root, a['href'])
                        if loc not in found_sitemaps:
                            urls = fetch_sitemap(loc)
                            if urls:
                                found_sitemaps.append(loc)
                                sitemap_urls_map[loc] = urls
                                time.sleep(0.2)
        except Exception:
            pass

        # Salva risultati nello scan_results (o dove preferisci)
        scan_results['sitemap'] = {
            'found_sitemaps': found_sitemaps,
            'sitemap_urls_map': sitemap_urls_map
        }




    except requests.exceptions.RequestException as e:
        scan_results['error'] = f"Errore durante la richiesta a {url}: {e}"

    return scan_results
