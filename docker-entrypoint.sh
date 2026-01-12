#!/bin/sh
set -eu

# genera config msmtp se presenti le env
if [ -n "${SMTP_HOST:-}" ] && [ -n "${SMTP_USER:-}" ] && [ -n "${SMTP_PASS:-}" ]; then
  cat > /etc/msmtprc <<EOC
defaults
auth on
tls on
tls_starttls on
logfile /dev/stdout

account default
host ${SMTP_HOST}
port ${SMTP_PORT:-587}
user ${SMTP_USER}
password ${SMTP_PASS}
from ${SMTP_FROM:-$SMTP_USER}
EOC
  chmod 600 /etc/msmtprc
fi

export MSMTP_PATH="${MSMTP_PATH:-/usr/bin/msmtp}"

exec uvicorn web_app:app --host 0.0.0.0 --port 8001
