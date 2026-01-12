#!/bin/sh
set -eu

if [ -n "${SMTP_HOST:-}" ] && [ -n "${SMTP_USER:-}" ] && [ -n "${SMTP_PASS:-}" ]; then
  PORT="${SMTP_PORT:-587}"

  {
    echo "defaults"
    echo "auth on"
    echo "tls on"
    # STARTTLS solo su 587/25, NON su 465
    if [ "$PORT" = "465" ]; then
      echo "tls_starttls off"
    else
      echo "tls_starttls on"
    fi
    echo "timeout 10"
    echo "logfile /dev/stdout"
    echo ""
    echo "account default"
    echo "host ${SMTP_HOST}"
    echo "port ${PORT}"
    echo "user ${SMTP_USER}"
    echo "password ${SMTP_PASS}"
    echo "from ${SMTP_FROM:-$SMTP_USER}"
  } > /etc/msmtprc

  chmod 600 /etc/msmtprc
fi

export MSMTP_PATH="${MSMTP_PATH:-/usr/bin/msmtp}"
exec uvicorn web_app:app --host 0.0.0.0 --port 8001
