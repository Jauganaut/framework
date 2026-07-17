#!/bin/sh

set -e

if [ -n "${BITB_OPEN_URL}" ]; then
  export FF_OPEN_URL="${BITB_OPEN_URL}"
fi

exec /usr/bin/firefox --kiosk "$FF_OPEN_URL"
