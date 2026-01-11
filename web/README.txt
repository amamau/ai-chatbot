============================================================
AMAMAU insight AI — RUNBOOK COMPLETO (VPS + NGINX + FASTAPI)
============================================================

Ultimo aggiornamento: 2025-12-10
Server: OVH VPS-1, Ubuntu 25.04
Hostname: vps-ac1b3bd5.vps.ovh.net
IP: 57.131.24.204
Dominio: ai.amamau.com
Utente: ubuntu

Stack
-----
• Reverse proxy: Nginx (porta 80/443)
• Backend: FastAPI + Uvicorn (porta 8001, solo localhost)
• LLM: DeepSeek via API (chiave in variabile d’ambiente)
• Frontend: HTML/CSS/JS statici in ./web
• Auth: link con token univoco /t/<TOKEN> → profilo business (JSON)
• Dati: profili, mapping token, memoria per profilo in ./data/

Cartella progetto
-----------------
Percorso principale:

  /home/ubuntu/amamau/ai-chatbot

Contenuto chiave:

  README.txt              ← questo runbook (o nome simile)
  requirements.txt        ← librerie Python
  web_app.py              ← backend FastAPI per servizio web (usato da Nginx)
  main.py                 ← CLI / assistant in terminale (per owner)
  llm_client.py           ← wrapper DeepSeek (logica chiamate ai modello)
  prompts.py              ← prompt di sistema per assistant business
  profiles.py             ← gestione profili business + token
  memory.py               ← gestione memoria per profilo
  tokens.py               ← generazione token random sicuri
  config.py               ← config generali (path base ecc.)

  data/
    profiles.json         ← profili business (id, nome, descrizione, ecc.)
    tokens.json           ← mapping token → profili (token, profile_id, label…)
    memory/
      <profile_id>.md     ← memoria long-term per singolo profilo

  web/
    index.html            ← landing pubblica ai.amamau.com
    chat.html             ← console web per /t/<TOKEN>
    logo-amamau.svg
    mark-amamau-white.svg
    ...                   ← eventuali altri asset

  venv/
    ...                   ← virtualenv Python (non da committare)

============================================================
1. PRE-REQUISITI SUL VPS
============================================================

1.1. Pacchetti base
-------------------

  sudo apt update
  sudo apt install -y python3 python3-venv python3-pip nginx git

Se usi Certbot per HTTPS (Let’s Encrypt):

  sudo apt install -y certbot python3-certbot-nginx

1.2. Firewall UFW
-----------------
Configurazione nota (già impostata):

  sudo ufw status

Regole base consigliate:

  sudo ufw default deny incoming
  sudo ufw default allow outgoing

  # SSH personalizzato (già configurato)
  sudo ufw allow 59281/tcp

  # HTTP/HTTPS
  sudo ufw allow 80/tcp
  sudo ufw allow 443/tcp

  sudo ufw enable

============================================================
2. PYTHON / VENV / DEPENDENZE
============================================================

2.1. Creazione virtualenv
-------------------------

  cd ~/amamau/ai-chatbot
  python3 -m venv venv

2.2. Attivazione venv
---------------------

Ogni volta che lavori sul progetto:

  cd ~/amamau/ai-chatbot
  source venv/bin/activate

Per uscire dalla venv:

  deactivate

2.3. Installazione dipendenze
-----------------------------

  (venv) pip install --upgrade pip
  (venv) pip install -r requirements.txt

requirements.txt dovrebbe includere (minimo):

  fastapi
  uvicorn[standard]
  httpx
  pydantic
  python-dotenv   # se usata
  # + eventuali librerie extra usate nel codice

============================================================
3. VARIABILI D’AMBIENTE (DEEPSEEK & CO.)
============================================================

Modifica ~/.bashrc:

  nano ~/.bashrc

Aggiungi (sostituendo la chiave con quella reale):

  export DEEPSEEK_API_KEY="sk-XXXXXXXXXXXXXXXX"

Eventuali altre variabili (se usate dal codice):

  export AMAMAU_AI_OWNER_EMAIL="hello@amamau.com"
  export SMTP_HOST="smtp.xxx"
  export SMTP_USER="user"
  export SMTP_PASS="password"

Ricarica ambiente:

  source ~/.bashrc

Verifica:

  echo $DEEPSEEK_API_KEY

============================================================
4. STRUTTURA LOGICA DEL SERVIZIO
============================================================

4.1. Frontend
-------------

• ai.amamau.com/        → landing pubblica (index.html)
• ai.amamau.com/t/TOKEN → console chat per profilo collegato a TOKEN (chat.html)
• assets                → serviti direttamente da Nginx dalla cartella ./web

4.2. Backend (FastAPI)
----------------------

Porta: 8001 su localhost.

Route principali in web_app.py:

  GET /               → FileResponse(web/index.html)
  GET /t/{token}      → FileResponse(web/chat.html)
  POST /api/chat      → JSON { token, message } → chiama DeepSeek → risposta
  GET /api/health     → {"status": "ok"}

4.3. Profili / token / memoria
------------------------------

File: data/profiles.json

  {
    "profiles": [
      {
        "id": "thita",
        "name": "THITA",
        "description": "Brand di prodotti fisici premium...",
        "language": "it",
        "industry": "design / e-commerce DTC",
        "tagline": "Business assistant per margini, pricing e lancio DTC.",
        "notes": "Target uomini 25-40 anni, tech/creativi..."
      }
      # altri profili...
    ]
  }

File: data/tokens.json

  {
    "tokens": [
      {
        "token": "GclkatIITC6d-X0MLnfPdnf3jPArkb0yfwOwgmfBchqqb0hrF",
        "profile_id": "thita",
        "label": "THITA main beta",
        "created_at": "2025-12-10T19:45:00Z",
        "active": true
      }
      # altri token...
    ]
  }

Memoria: data/memory/<profile_id>.md

  [2025-12-10 18:32] Margine lordo minimo 55% su ogni prodotto fisico.
  [2025-12-10 18:40] Solo DTC per 18 mesi, no Amazon.
  ...

============================================================
5. BACKEND FASTAPI (web_app.py)
============================================================

Schema logico (semplificato):

  from fastapi import FastAPI, HTTPException
  from fastapi.responses import FileResponse
  from fastapi.middleware.cors import CORSMiddleware
  from pydantic import BaseModel
  from pathlib import Path

  from profiles import get_profile_by_token
  from llm_client import generate_business_reply
  from memory import append_memory_note

  BASE_DIR = Path(__file__).resolve().parent
  WEB_DIR = BASE_DIR / "web"

  app = FastAPI()

  app.add_middleware(
      CORSMiddleware,
      allow_origins=["https://ai.amamau.com", "http://localhost"],
      allow_methods=["*"],
      allow_headers=["*"],
  )

  class ChatRequest(BaseModel):
      token: str
      message: str

  @app.get("/")
  async def root():
      return FileResponse(WEB_DIR / "index.html")

  @app.get("/t/{token}")
  async def chat_page(token: str):
      return FileResponse(WEB_DIR / "chat.html")

  @app.post("/api/chat")
  async def api_chat(payload: ChatRequest):
      profile = get_profile_by_token(payload.token)
      if not profile or not profile.get("active", True):
          raise HTTPException(status_code=401, detail="Invalid or inactive token")

      reply, memory_note = await generate_business_reply(
          profile=profile,
          user_message=payload.message,
      )

      if memory_note:
          append_memory_note(profile["id"], memory_note)

      return {
          "reply": reply,
          "profile_name": profile.get("name"),
          "profile_tagline": profile.get("tagline", "")
      }

  @app.get("/api/health")
  async def health():
      return {"status": "ok"}

============================================================
6. LLM CLIENT (llm_client.py) + PROMPT (prompts.py)
============================================================

6.1. LLM client (schema)
------------------------

• Usa httpx o requests per chiamare DeepSeek.
• Inietta BUSINESS_SYSTEM_PROMPT (prompts.py) come system message.
• Aggiunge contesto del profilo (segmento, target, obiettivi).
• Applica regole:
  - Niente vera navigazione internet; solo simulazioni basate su dati storici.
  - Focalizzazione su business, pricing, funnel, strategia.
  - Devia le domande fuori tema riportando al business del profilo.

Funzione principale:

  async def generate_business_reply(profile, user_message: str) -> tuple[str, str | None]:
      """
      Ritorna:
        reply       → testo da mandare al client
        memory_note → stringa da salvare in memoria (o None)
      """

6.2. Prompt di sistema (prompts.py)
-----------------------------------

Contiene una stringa multilinea, ad esempio:

  BUSINESS_SYSTEM_PROMPT = """
  Sei un assistente business per amamau, specializzato in:
  - pricing, marginalità, unit economics
  - funnel, go-to-market, roadmap
  - posizionamento per piccoli brand DTC, SaaS, studi

  Regole:
  1) Rispondi sempre nella lingua del profilo (it/en).
  2) Non accedere a internet né inventare ricerche di mercato live.
     Puoi solo simulare scenari basandoti su conoscenza generale.
  3) Se la domanda è completamente fuori dal business (es: fisica dei buchi neri),
     rispondi brevemente che non è il tuo ambito e riporti la conversazione
     su pricing, strategia, margini, funnel o posizionamento.
  4) Tieni conto di target, margini e vincoli dal profilo e dalla memoria.
  5) Risposte pratiche, con numeri e azioni, non teoria astratta.
  """

============================================================
7. GESTIONE PROFILI E TOKEN (profiles.py / tokens.py / memory.py)
============================================================

7.1. Funzioni tipiche (profiles.py)
-----------------------------------

• load_profiles()               → legge data/profiles.json
• save_profiles(data)           → scrive data/profiles.json
• get_profile_by_id(profile_id) → restituisce il profilo
• get_profile_by_token(token)   → legge data/tokens.json, trova profile_id, carica profilo
• create_profile(...)           → aggiunge nuovo profilo
• edit_profile(...)             → aggiorna campi di un profilo

7.2. Gestione token (tokens.py)
-------------------------------

• load_tokens() / save_tokens()
• generate_secure_token(length=50)
  - usa secrets.token_urlsafe() o simile
• bind_token_to_profile(token, profile_id, label="...", active=True)

Formato token:
  - stringa random 40–64 caratteri
  - caratteri ammessi: lettere, numeri, -, _ (url-safe)

7.3. Memoria (memory.py)
------------------------

• append_memory_note(profile_id, note: str):
  - apre/crea data/memory/<profile_id>.md
  - aggiunge riga "[timestamp] note"

============================================================
8. FRONTEND STATICO (web/index.html e web/chat.html)
============================================================

8.1. index.html (landing)
-------------------------

• Stile Apple-like, coerente con sito amamau principale:
  - header sticky con logo-amamau.svg
  - layout .shell con max-width 1120px, background #f5f5f7
  - hero con titolo "Digital tools that don’t look cheap" ecc.
  - sezioni “Current lineup”, “Approach”, “Contact”, “Footer”
  - pulsanti:
    • “View the lineup” → #products
    • “Discuss a project” → mailto:hello@amamau.com

• Puoi aggiungere un’area “Accesso” per token:

  <!-- Esempio form accesso token -->
  <section class="section">
    <div class="section-header">
      <div class="tagline">Private layer</div>
      <h2 class="section-title">Access your business console.</h2>
      <p class="section-sub">
        Paste your private token to open the console scoped to your profile.
      </p>
    </div>
    <form onsubmit="event.preventDefault(); goToToken();">
      <input id="tokenInput" type="text"
             placeholder="Paste your access token"
             style="padding:0.7rem 0.9rem; border-radius:999px; border:1px solid #dcdce4; width:100%; max-width:380px; font-size:0.9rem;">
      <button type="submit" class="btn btn-primary" style="margin-top:0.8rem;">
        Access console
      </button>
    </form>
  </section>

  <script>
    function goToToken() {
      const el = document.getElementById('tokenInput');
      const token = (el.value || '').trim();
      if (!token) return;
      window.location.href = '/t/' + encodeURIComponent(token);
    }
  </script>

8.2. chat.html (console /t/{token})
-----------------------------------

Caratteristiche principali:

• Header:
  - logo minimale (“AMAMAU • AI”)
  - pill "Private beta · internal / client"
  - chip che mostra token abbreviato "Token · abcde…xyz"
  - link “Back to overview” → "/"

• Card centrale:
  - container .chat-shell con:
    - console-header (titolo + tags)
    - chat-body (lista messaggi)
    - input-wrap (textarea + bottone)

• JS:
  - ricava token dalla URL:

    const pathParts = window.location.pathname.split('/').filter(Boolean);
    const token = pathParts.length >= 2 ? pathParts[1] : '';

  - aggiorna chip token:
    shortToken = token.length > 20
      ? token.slice(0, 10) + '…' + token.slice(-6)
      : token || 'missing';

  - appendMessage(role, text): crea bubble per user/ai
  - appendTyping() / removeTyping(): 3 pallini animati
  - sendMessage():
      • invia POST /api/chat con JSON { token, message }
      • se ok → mostra reply + aggiorna header con profile_name/profile_tagline
      • se errore → bubble con testo di errore ("token invalido", "backend down", ecc.)

• Input:
  - Invio              → manda messaggio
  - Shift+Invio        → va a capo
  - autosize textarea  → altezza fino a max 120px

============================================================
9. NGINX: CONFIG COMPLETA
============================================================

9.1. File di sito
-----------------

Percorso:

  /etc/nginx/sites-available/ai.amamau.com

Contenuto esempio:

  server {
      listen 80;
      listen [::]:80;
      server_name ai.amamau.com;

      # Redirect a HTTPS
      return 301 https://$host$request_uri;
  }

  server {
      listen 443 ssl http2;
      listen [::]:443 ssl http2;
      server_name ai.amamau.com;

      ssl_certificate     /etc/letsencrypt/live/ai.amamau.com/fullchain.pem;
      ssl_certificate_key /etc/letsencrypt/live/ai.amamau.com/privkey.pem;

      root /home/ubuntu/amamau/ai-chatbot/web;
      index index.html;

      access_log /var/log/nginx/ai-amamau-access.log;
      error_log  /var/log/nginx/ai-amamau-error.log;

      # Console /t/<token> → backend FastAPI
      location ^~ /t/ {
          proxy_pass http://127.0.0.1:8001;
          proxy_http_version 1.1;
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;
      }

      # API → backend FastAPI
      location ^~ /api/ {
          proxy_pass http://127.0.0.1:8001;
          proxy_http_version 1.1;
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;
      }

      # Statico → index.html e file nella cartella ./web
      location / {
          try_files $uri /index.html;
      }
  }

Attenzione:
• location ^~ /t/ e ^~ /api/ DEVONO stare sopra location /.
• root punta EXACT a /home/ubuntu/amamau/ai-chatbot/web.

9.2. Abilitare il sito
----------------------

  sudo ln -s /etc/nginx/sites-available/ai.amamau.com /etc/nginx/sites-enabled/ai.amamau.com

Test config:

  sudo nginx -t

Reload:

  sudo systemctl reload nginx

============================================================
10. CERTIFICATI HTTPS (Let’s Encrypt) — opzionale se già fatto
============================================================

Se non hai ancora HTTPS:

  sudo certbot --nginx -d ai.amamau.com

Certbot modificherà automaticamente il blocco server, aggiungendo ssl_certificate e redirect.

============================================================
11. DNS PER ai.amamau.com
============================================================

Su provider DNS (es. Aruba):

• Record A:
  Tipo: A
  Nome: ai
  Valore: 57.131.24.204
  TTL: 300–600

Puoi verificare da locale:

  dig ai.amamau.com
  ping ai.amamau.com

============================================================
12. AVVIO BACKEND (Uvicorn / systemd)
============================================================

12.1. Avvio manuale
-------------------

  cd ~/amamau/ai-chatbot
  source venv/bin/activate
  python -m uvicorn web_app:app --host 127.0.0.1 --port 8001

Se ricevi:
  ERROR: [Errno 98] address already in use

→ c’è già un processo su 8001:

  sudo ss -lptn 'sport = :8001'
  # oppure
  ps aux | grep uvicorn

Kill processo:

  sudo kill <PID>
  # oppure più brutale
  sudo kill -9 <PID>

Poi rilancia uvicorn.

12.2. Avvio come servizio systemd (consigliato)
-----------------------------------------------

Crea:

  sudo nano /etc/systemd/system/amamau-ai.service

Inserisci:

  [Unit]
  Description=amamau insight AI backend
  After=network.target

  [Service]
  User=ubuntu
  WorkingDirectory=/home/ubuntu/amamau/ai-chatbot
  Environment="DEEPSEEK_API_KEY=sk-XXXXXXXXXXXXXXXX"
  ExecStart=/home/ubuntu/amamau/ai-chatbot/venv/bin/python -m uvicorn web_app:app --host 127.0.0.1 --port 8001
  Restart=always
  RestartSec=3

  [Install]
  WantedBy=multi-user.target

Attiva e avvia:

  sudo systemctl daemon-reload
  sudo systemctl enable amamau-ai
  sudo systemctl start amamau-ai
  sudo systemctl status amamau-ai

Log:

  journalctl -u amamau-ai -n 50
  journalctl -u amamau-ai -f

============================================================
13. TEST E DEBUG
============================================================

13.1. Test backend da VPS
-------------------------

  curl http://127.0.0.1:8001/api/health
  → {"status":"ok"}

13.2. Test Nginx + backend da remoto
------------------------------------

  curl -I https://ai.amamau.com/
  → 200 OK (landing)

  curl -I https://ai.amamau.com/t/test123
  → 200 OK (chat.html servito via backend)

  curl -X POST https://ai.amamau.com/api/chat \
       -H 'Content-Type: application/json' \
       -d '{"token": "TOKEN_FINTA", "message": "Ciao"}'

13.3. Log
---------

Nginx error:

  sudo tail -n 100 /var/log/nginx/ai-amamau-error.log

Nginx access:

  sudo tail -n 100 /var/log/nginx/ai-amamau-access.log

Backend (se systemd):

  journalctl -u amamau-ai -n 100
  journalctl -u amamau-ai -f

============================================================
14. MANUTENZIONE PROFILI / TOKEN
============================================================

14.1. Via CLI (se main.py supporta gestione)
-------------------------------------------

  cd ~/amamau/ai-chatbot
  source venv/bin/activate
  python main.py

Possibile menu:

  1) Start assistant for a profile (CLI)
  2) Edit existing profile
  3) Manage tokens
  4) Exit

Sotto Manage tokens:
• crea nuovo token (lunghezza 50) per un profilo esistente
• revoca token (active: false)
• lista token attivi

14.2. Modifica manuale JSON
---------------------------

Profili:

  nano data/profiles.json

Token:

  nano data/tokens.json

Regole:
• Ogni token deve avere profile_id che esiste in profiles.json.
• Per revocare accesso: active: false o rimuovere entry.
• Fai attenzione a virgole e parentesi (JSON valido).

============================================================
15. BACKUP & UPDATE
============================================================

15.1. Backup periodico
----------------------

Cartelle/file critici:

  ~/amamau/ai-chatbot/data/profiles.json
  ~/amamau/ai-chatbot/data/tokens.json
  ~/amamau/ai-chatbot/data/memory/
  ~/amamau/ai-chatbot/web/ (se personalizzato rispetto a repo)

Esempio backup:

  cd ~/amamau
  tar czf ai-chatbot-backup-$(date +%Y%m%d).tar.gz ai-chatbot/data ai-chatbot/web

Copia il .tar.gz altrove (altro server / S3 / ecc.).

15.2. Aggiornare codice
-----------------------

  cd ~/amamau/ai-chatbot
  source venv/bin/activate
  git pull           # se repo versionata
  pip install -r requirements.txt

Se usi systemd:

  sudo systemctl restart amamau-ai

============================================================
16. CHECKLIST RAPIDA (OPERAZIONI)
============================================================

A. NUOVO DEPLOY/AGGIORNAMENTO
-----------------------------

1) Backup data/ e web/ (vedi sezione 15.1)
2) git pull (se usi git) oppure aggiorna file.
3) pip install -r requirements.txt
4) sudo systemctl restart amamau-ai
5) sudo nginx -t && sudo systemctl reload nginx
6) Test:
   - curl http://127.0.0.1:8001/api/health
   - apri https://ai.amamau.com/
   - apri https://ai.amamau.com/t/<TOKEN_VALIDO>

B. NUOVO PROFILO + TOKEN PER BETA TESTER
----------------------------------------

1) Aggiungi profilo in data/profiles.json (o usa CLI)
   - id: stringa semplice (es. "cliente_x")
2) Genera token:
   - via CLI oppure crea entry in data/tokens.json:

     {
       "token": "<TOKEN_RANDOM>",
       "profile_id": "cliente_x",
       "label": "Cliente X beta",
       "created_at": "2025-12-10T20:00:00Z",
       "active": true
     }

3) Nessun riavvio necessario, ma puoi:
   - sudo systemctl restart amamau-ai (facoltativo)
4) Invia al cliente:
   - URL: https://ai.amamau.com/t/<TOKEN_RANDOM>

C. PROBLEMI TIPICI
------------------

• Vedo ancora la index su /t/<token>:
  - controlla Nginx:
    - location ^~ /t/ deve esistere prima di location /
    - sudo nginx -t
    - sudo systemctl reload nginx

• “Invalid or inactive token”:
  - controlla data/tokens.json:
    - token corretto?
    - active: true?
  - /api/chat usa payload.token; se index/chat è ok ma token sbagliato, errore atteso.

• L’AI parla di cose random e non business:
  - rivedi BUSINESS_SYSTEM_PROMPT in prompts.py
  - controlla che generate_business_reply usi quello prompt e info profilo.

============================================================
FINE RUNBOOK COMPLETO AMAMAU insight AI
============================================================
