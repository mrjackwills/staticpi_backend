#!/bin/bash
set -e

create_staticpi_user() {
	echo "create_staticpi_user"
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_USER" <<-EOSQL
		CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASSWORD}';
	EOSQL
}

bootstrap_from_sql_file() {
	psql -U "$POSTGRES_USER" -d postgres -f /init/init_db.sql
}

restore_pg_dump() {
	echo "restore_pg_dump"
	pg_restore -U "$POSTGRES_USER" -O --exit-on-error --single-transaction -d "$DB_NAME" -v /init/pg_dump.tar
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
		GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO ${DB_NAME};
		GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ${DB_NAME};
	EOSQL
}

create_staticpi_database() {
	echo "create_staticpi_database"
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_USER" <<-EOSQL
		CREATE DATABASE ${DB_NAME};
	EOSQL
}

update_banned_domains() {
	echo "update_banned_domains"
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$DB_NAME" <<-EOSQL
		DELETE FROM banned_email_domain;
		COPY banned_email_domain (domain) FROM '/init/banned_domains.txt';
		GRANT USAGE, SELECT ON SEQUENCE banned_email_domain_banned_email_domain_id_seq TO $DB_NAME;
		GRANT ALL ON banned_email_domain TO $DB_NAME;
		GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO $DB_NAME;
		GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_NAME;
	EOSQL
}

from_pg_dump() {
	create_staticpi_user
	create_staticpi_database
	restore_pg_dump
	update_banned_domains
}

from_scratch() {
	create_staticpi_user
	bootstrap_from_sql_file
	update_banned_domains
}

main() {
	if [ -f "/init/pg_dump.tar" ]; then
		from_pg_dump
	else
		from_scratch
	fi
}

main
