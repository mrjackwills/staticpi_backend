#!/bin/sh

API_PORT=$(grep "API_PORT" /app_env/.api.env | cut -c 10-13)
TOKEN_PORT=$(grep "TOKEN_PORT" /app_env/.api.env | cut -c 12-15)
WS_PORT=$(grep "WS_PORT" /app_env/.api.env | cut -c 9-12)

# Automatically updated on ./create_release.sh
API_URL="staticpi_api:${API_PORT}/v0/incognito/online"

TOKEN_URL="staticpi_api:${TOKEN_PORT}/online"

WSS_URL="ws://staticpi_api:${WS_PORT}/online"

wget -nv -t1 --spider "${API_URL}" || exit 1

wget -nv -t1 --spider "${TOKEN_URL}" || exit 1

/healthcheck/websocat "${WSS_URL}" -q -E > /dev/null 2>&1

sleep 1

exit $?

