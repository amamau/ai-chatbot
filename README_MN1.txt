AMAMAU AI — MANUTENZIONE & DEPLOY README
======================================

Sistema:
- VPS: OVH
- OS: Ubuntu 25.04
- Dominio: ai.amamau.com
- Reverse proxy: Nginx + SSL Let's Encrypt
- Backend: FastAPI + Uvicorn
- Python: 3.x (venv)
- Porta backend: 8001
- Porta pubblica: 443 (HTTPS)

Percorsi fondamentali
---------------------
ROOT PROGETTO (LIVE):
/home/ubuntu/amamau/ai-chatbot

VENV:
/home/ubuntu/amamau/ai-chatbot/venv

NGINX VHOST:
/etc/nginx/sites-available/ai-amamau
/etc/nginx/sites-enabled/ai-amamau

SYSTEMD SERVICE:
/etc/systemd/system/amamau-ai.service

SSL:
/etc/letsencrypt/live/ai.amamau.com/


ARCHITETTURA
------------
Internet
  ?
Cloudflare (DNS / Proxy)
  ?
Nginx (443 HTTPS)
  ?
proxy_pass http://127.0.0.1:8001
  ?
Uvicorn (FastAPI)
  ?
AMAMAU AI backend


SYSTEMD SERVICE (CONFIG CORRETTA)
--------------------------------
[Unit]
Description=AMAMAU AI Backend (uvicorn)
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/amamau/ai-chatbot
Environment=PYTHONUNBUFFERED=1
ExecStart=/home/ubuntu/amamau/ai-chatbot/venv/bin/uvicorn web_app:app --host 127.0.0.1 --port 8001
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target


NGINX VHOST (CONFIG CORRETTA)
----------------------------
server {
    listen 443 ssl http2;
    server_name ai.amamau.com;

    ssl_certificate /etc/letsencrypt/live/ai.amamau.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ai.amamau.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
    }
}

server {
    listen 80;
    server_name ai.amamau.com;
    return 301 https://$host$request_uri;
}


DIPENDENZE OBBLIGATORIE (requirements.txt)
-----------------------------------------
fastapi
uvicorn[standard]
python-multipart
(piu` tutte le altre del progetto)


COMANDI DI ROUTINE
------------------

Restart backend:
sudo systemctl restart amamau-ai.service

Status backend:
sudo systemctl status amamau-ai.service --no-pager

Log backend:
sudo journalctl -u amamau-ai.service -n 100 --no-pager

Test backend locale:
curl -i http://127.0.0.1:8001/

Test porta:
sudo ss -ltnp | grep 8001

Reload nginx:
sudo systemctl reload nginx

Test nginx:
sudo nginx -t


DEPLOY NUOVA VERSIONE (SAFE)
----------------------------
1) Carica nuova versione in:
   /home/ubuntu/amamau/ai-chatbot

2) Aggiorna dipendenze:
   ./venv/bin/pip install -r requirements.txt

3) Test sintassi:
   ./venv/bin/python -m py_compile web_app.py

4) Restart:
   sudo systemctl restart amamau-ai.service

5) Test:
   curl -i http://127.0.0.1:8001/


ERRORI COMUNI & SOLUZIONI
------------------------

502 Bad Gateway:
- Backend NON in ascolto
  ? curl 127.0.0.1:8001
  ? journalctl -u amamau-ai

status=203/EXEC:
- venv mancante o uvicorn non installato
  ? pip install uvicorn fastapi

ImportError:
- mismatch tra web_app.py e chat_db.py
  ? aggiungere stub o riallineare versioni

RuntimeError: python-multipart:
- dipendenza mancante
  ? pip install python-multipart

Porta non aperta:
- backend crasha in startup
  ? leggere SEMPRE journalctl


REGOLE D’ORO (NON NEGOZIABILI)
-----------------------------
- MAI sovrascrivere a caso senza backup
- MAI cambiare porta backend senza Nginx
- MAI deploy senza test locale su 127.0.0.1
- MAI lasciare 2 servizi Uvicorn attivi
- MAI dimenticare requirements.txt


CHECKLIST POST-DEPLOY
---------------------
[ ] curl 127.0.0.1:8001 ? 200/302
[ ] https://ai.amamau.com carica
[ ] systemctl status amamau-ai = active
[ ] ss -ltnp mostra LISTEN 8001
[ ] snapshot VPS


NOTE FINALI
-----------
Questo README è la fonte di verità.
Se qualcosa va storto:
1) systemd
2) journalctl
3) curl locale
4) Nginx

In questo ordine. Sempre.

AMAMAU AI — produzione stabile.
