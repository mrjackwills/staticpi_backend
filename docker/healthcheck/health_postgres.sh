#!/bin/sh
set -e

main() {
	PONG=$(pg_isready -U "$DB_NAME" -p "${DOCKER_PG_PORT}")
	if expr "$PONG" : "/var/run/postgresql:${DOCKER_PG_PORT} - accepting connections" >/dev/null; then
		return
	else
		return 1
	fi
}

main
