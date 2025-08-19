import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

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
        'custom_data': {} # Per i dati specifici che vuoi estrarre
    }
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
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
