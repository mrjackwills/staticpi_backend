#!/bin/sh -x
set -e

# Should really use wait-for here
DEV_DB=dev_${DB_NAME}

bootstrap_from_sql_file() {
	psql -U "$POSTGRES_USER" -d postgres -f /init/init_db.sql
}

create_staticpi_user() {
	echo "create_staticpi_user"
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "postgres" <<-EOSQL
		CREATE ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASSWORD';
		CREATE DATABASE $DB_NAME;
	EOSQL
}

restore_pg_dump() {
	echo "pg_restore"
	# Should use .sql instead, and then restore from backup? That way can make sure tables are setup correctly, and can also handle any migrations in an .sql file
	pg_restore -U "$POSTGRES_USER" -O --exit-on-error --single-transaction -d "$DB_NAME" -v /init/pg_dump.tar
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$DB_NAME" <<-EOSQL
		GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO $DB_NAME;
		GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_NAME;
	EOSQL
}

add_dev_staticpi() {
	echo "creating dev_staticpi"
	createdb -U "$POSTGRES_USER" -O "$POSTGRES_USER" -T "$DB_NAME" "$DEV_DB"

	echo "granting access on staticpi to staticpi"
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$DB_NAME" <<-EOSQL
		GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO $DB_NAME;
		GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_NAME;
	EOSQL

	echo "granting access on dev_staticpi to staticpi"
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$DEV_DB" <<-EOSQL
		GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO $DB_NAME;
		GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_NAME;
	EOSQL
}

banned_domains() {
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$DB_NAME" <<-EOSQL
		DELETE FROM banned_email_domain;
		COPY banned_email_domain (domain) FROM '/init/banned_domains.txt';
	EOSQL
}

from_scratch() {
	create_staticpi_user
	bootstrap_from_sql_file
	banned_domains
}

from_pg_dump() {
	create_staticpi_user
	restore_pg_dump
	banned_domains
}

main() {

	if [ -f "/init/pg_dump.tar" ]; then
		from_pg_dump
	else
		from_scratch
	fi
	add_dev_staticpi
}

main
