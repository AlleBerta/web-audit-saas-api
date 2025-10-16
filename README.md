# Web Audit SaaS - API

Questo è il repository per il server backend del progetto "Web Audit SaaS", sviluppato per un tirocinio universitario. Il server è responsabile di ricevere le richieste di analisi di un dominio, eseguire gli script di scraping e audit, e salvare i risultati.

## Funzionalità Principali

- Espone API per avviare nuove scansioni di domini.
- Utilizza script Python per eseguire le analisi.
- Salva i risultati delle scansioni in un database SQLite.
- Gestisce i log delle operazioni.

## Prerequisiti

Prima di iniziare, assicurati di avere installato:

- Python 3.8+
- pip
- virtualenv (consigliato)

## Esecuzione

Per avviare il server in modalità sviluppo, esegui lo script:

```bash
./flash.sh start
```

Il server sarà in ascolto all'indirizzo `http://127.0.0.1:5000`.

## Struttura del Progetto

Una breve descrizione dei file principali:

- `app.py`: Il file principale dell'applicazione Flask, gestisce le route API.
- `scraper.py`: Contiene la logica per lo scraping e l'analisi dei domini.
- `scansioni.db`: Il database SQLite dove vengono memorizzati i dati.
- `schema.sql`: Lo schema SQL per inizializzare il database.
- `outputs/`: Cartella dove vengono salvati eventuali file di output.
- `log.txt`: File di log delle operazioni del server.

## Installazione - Non aggiornato!!!

1.  **Clona la repository:**

    ```bash
    git clone https://github.com/AlleBerta/web-audit-saas-api.git
    cd web-audit-saas-backend
    ```

2.  **Crea e attiva un ambiente virtuale:**

    ```bash
    python -m venv venv
    source venv/bin/activate  # Su Windows: venv\Scripts\activate
    ```

3.  **Installa le dipendenze:**

    ```bash
    pip install -r requirements.txt
    ```

    _(Nota: file creato con `pip freeze > requirements.txt`)_

<!-- 4.  **Inizializza il database:**
    ```bash
    # Istruzioni per creare il db usando schema.sql
    # Esempio: sqlite3 scansioni.db < schema.sql
    ``` -->
