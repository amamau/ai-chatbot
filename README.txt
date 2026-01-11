###################################################################################################
#                                      AMAMAU INSIGHT AI                                          #
#                          DOCUMENTAZIONE TECNICA COMPLETA (VERSIONE TXT)                         #
###################################################################################################

Progetto: amamau Insight AI
Dominio: https://ai.amamau.com
Backend: FastAPI + Uvicorn
Frontend: HTML/CSS server-rendered
Proxy: Nginx
Service: systemd
Storage: JSON + RAM session store
Autore: amamau engineering
Livello: ENTERPRISE / INTERNAL USE ONLY


===================================================================================================
0. INTRODUZIONE
===================================================================================================
Questo documento contiene ogni informazione necessaria per:
- installare
- configurare
- mantenere
- aggiornare
- ripristinare
- auditare
il sistema Insight AI.

Il file è pensato per durare negli anni ed essere leggibile da qualsiasi tecnico.


===================================================================================================
1. ARCHITETTURA TECNICA
===================================================================================================

Schema generale:

Browser ? HTTPS ? Nginx ? Uvicorn (web_app.py) ? DeepSeek API

Componenti:
- Uvicorn esegue FastAPI
- web_app.py gestisce routing, login, OTP, sessioni, UI, history, account center
- accounts.py gestisce utenti, password, attivazioni, hashing bcrypt
- tokens.py gestisce profili LLM
- data/ contiene tutta la persistenza (users, profiles, history)
- Nginx funge da reverse proxy e SSL terminator
- systemd mantiene il servizio attivo


===================================================================================================
2. STRUTTURA DEL PROGETTO
===================================================================================================

ai-chatbot/
+-- web_app.py
+-- accounts.py
+-- tokens.py
+-- data/
¦   +-- users.json
¦   +-- profiles/
¦   +-- memory/
¦   +-- chat_history/
+-- venv/
+-- systemd service


===================================================================================================
3. INSTALLAZIONE SU VPS
===================================================================================================

3.1 Dipendenze
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-venv python3-pip nginx -y

3.2 Setup
cd ~/amamau
git clone <repo> ai-chatbot
cd ai-chatbot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

3.3 Test avvio
uvicorn web_app:app --host 127.0.0.1 --port 8001 --reload


===================================================================================================
4. CONFIGURAZIONE SYSTEMD (PRODUZIONE)
===================================================================================================

File: /etc/systemd/system/ai-chatbot.service

[Unit]
Description=amamau AI Chatbot backend
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/amamau/ai-chatbot
Environment="PATH=/home/ubuntu/amamau/ai-chatbot/venv/bin"
ExecStart=/home/ubuntu/amamau/ai-chatbot/venv/bin/uvicorn web_app:app --host 127.0.0.1 --port 8001
Restart=always

[Install]
WantedBy=multi-user.target

Comandi utili:
sudo systemctl daemon-reload
sudo systemctl start ai-chatbot
sudo systemctl enable ai-chatbot
sudo systemctl restart ai-chatbot
sudo systemctl status ai-chatbot
sudo journalctl -u ai-chatbot -f


===================================================================================================
5. CONFIGURAZIONE NGINX
===================================================================================================

File: /etc/nginx/sites-enabled/ai.amamau.com.conf

server {
    server_name ai.amamau.com;

    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}

Reload:
sudo nginx -t
sudo systemctl reload nginx


===================================================================================================
6. WORKFLOW DI DEPLOY (AGGIORNAMENTI)
===================================================================================================

cd ~/amamau/ai-chatbot
source venv/bin/activate
python -m py_compile web_app.py
sudo systemctl restart ai-chatbot
sudo journalctl -u ai-chatbot -f

Se non ci sono errori, l’update è completato.


===================================================================================================
7. GESTIONE UTENTI (users.json)
===================================================================================================

Struttura user:
{
  "email": "user@example.com",
  "name": "User",
  "password_hash": "...bcrypt...",
  "is_active": true,
  "profile_id": "default"
}

Aggiungere un utente:
python3
import json, bcrypt
users=json.load(open("data/users.json"))
users.append({
  "email":"new@example.com",
  "name":"New",
  "password_hash":bcrypt.hashpw("Password123".encode(),bcrypt.gensalt()).decode(),
  "is_active":True,
  "profile_id":"default"
})
json.dump(users, open("data/users.json","w"), indent=2)
exit()

Reset password:
python3
import json,bcrypt
email="target@example.com"
users=json.load(open("data/users.json"))
for u in users:
    if u["email"].lower()==email.lower():
        u["password_hash"]=bcrypt.hashpw("NewPass123".encode(),bcrypt.gensalt()).decode()
json.dump(users, open("data/users.json","w"), indent=2)
exit()


===================================================================================================
8. SISTEMA OTP
===================================================================================================

Tipi di OTP:
- OTP login
- OTP cambio email

Archiviazione:
- OTP_STORE
- ACCOUNT_OTP_STORE
(solamente in RAM ? reset al riavvio)

Durata: 10 minuti

Comportamento login:
1. email + password
2. generazione OTP
3. invio mail
4. utente inserisce codice
5. sessione creata (ai_session)

Comportamento cambio email:
1. utente inserisce nuova email + password attuale
2. invio OTP alla nuova email
3. verifica OTP
4. users.json aggiornato
5. sessione aggiornata automaticamente


===================================================================================================
9. SISTEMA SESSIONI
===================================================================================================

Struttura SESSION_STORE:

{
  "session_id": {
    "email":"user@example.com",
    "created_at": datetime
  }
}

Il cookie si chiama ai_session. Le sessioni si cancellano al riavvio del servizio.


===================================================================================================
10. SISTEMA CHAT E LLM
===================================================================================================

Endpoint:
POST /api/chat

Request:
{
  "message":"Hello",
  "profile_id":"default"
}

Response:
{
  "reply":"Hi!"
}

Il profilo scelto definisce:
- modello usato
- stile risposta
- parametri LLM
- memoria


===================================================================================================
11. STORICO CHAT (HISTORY)
===================================================================================================

Percorso file:
data/chat_history/<email_slug>.jsonl

Formato JSONL:
{"ts":"...","role":"user","text":"Hi","profile_id":"default"}
{"ts":"...","role":"assistant","text":"Hello","profile_id":"default"}

Viewer:
GET /history


===================================================================================================
12. ACCOUNT CENTER
===================================================================================================

Pagina: /account

Consente:
- Cambio nome
- Cambio email (con OTP)
- Cambio password
- Visualizzazione email attuale

Sicurezza:
- Verifica password attuale prima dei cambiamenti sensibili
- OTP inviato alla nuova email
- Controlli anti-duplicazione account
- Sessione aggiornata dopo cambio email


===================================================================================================
13. BACKUP & DISASTER RECOVERY
===================================================================================================

Backup completo:
cp -r ~/amamau/ai-chatbot/data ~/backups/backup-$(date +%F)

Backup utenti:
cp data/users.json users-backup.json

Backup history:
cp -r data/chat_history history-backup/

Ripristino:
rm -rf data
cp -r ~/backups/... data


===================================================================================================
14. SICUREZZA
===================================================================================================

Elementi di sicurezza implementati:
? HTTPS obbligatorio
? Nessuna API pubblica
? Sessioni server-side
? Password hash bcrypt
? OTP volatile con scadenza
? users.json non accessibile al pubblico
? Nessuna chiave API esposta nel frontend
? Verifica password prima modifiche critiche

Controlli periodici:
sudo journalctl -u ai-chatbot | grep ERROR
sudo tail -n 50 /var/log/nginx/error.log


===================================================================================================
15. DEBUG E TOOLING
===================================================================================================

Verificare sintassi Python:
python -m py_compile web_app.py

Controllare stato servizio:
sudo systemctl status ai-chatbot

Logs realtime:
sudo journalctl -u ai-chatbot -f

Test API:
curl -X POST http://127.0.0.1:8001/api/chat \
     -H "Content-Type: application/json" \
     -d '{"message":"Test","profile_id":"default"}'


===================================================================================================
16. CHEAT SHEET (COMANDI PIÙ USATI)
===================================================================================================

cd ~/amamau/ai-chatbot
source venv/bin/activate
python -m py_compile web_app.py
sudo systemctl restart ai-chatbot
sudo journalctl -u ai-chatbot -f

Backup:
cp -r data backup-$(date +%F)

Ripristino:
cp -r backup-folder/data data


===================================================================================================
17. NOTE PER SVILUPPATORI FUTURI
===================================================================================================

- Tutto il backend gira in RAM: veloce, ma attenzione ai riavvii.
- users.json è la singola verità sull’autenticazione.
- Le OTP non persistono: non salvare log critici lì dentro.
- In caso di crash improvvisi, verificare sempre:
    ? web_app.py
    ? accounts.py
    ? tokens.py
    ? state utenti
    ? eventuale codice unicode corrotto

- Evitare caratteri unicode non ASCII nelle stringhe Python:
    utilizzare invece entità HTML (&bull; &copy; &ndash;).


===================================================================================================
18. PIANO DI RECUPERO DA INCIDENTI
===================================================================================================

Scenario A — Servizio non parte:
1. sudo journalctl -u ai-chatbot -n 50
2. python -m py_compile web_app.py
3. verificare Nginx: sudo nginx -t
4. fixare errori
5. sudo systemctl restart ai-chatbot

Scenario B — users.json corrotto:
1. cp users-backup.json users.json
2. riavviare servizio

Scenario C — history mancante:
1. ricreare cartella: mkdir -p data/chat_history

Scenario D — OTP non funzionano:
1. verificare _send_email
2. verificare logs email


===================================================================================================
19. ROADMAP POSSIBILE
===================================================================================================

- Conversation titles
- Multi-device sessions
- Profilazione avanzata
- Rate limiting per abuse prevention
- Encryption at-rest opzionale
- Versionamento configurazioni


###################################################################################################
#                       FINE README COMPLETO (VERSIONE TXT AMAMAU)                               #
###################################################################################################
