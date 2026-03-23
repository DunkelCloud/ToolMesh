#!/bin/bash
set -e

# This script runs inside the PostgreSQL container on first startup.
# It creates the Temporal user and databases using credentials from
# environment variables passed via docker-compose.yml.

TEMPORAL_USER="${TEMPORAL_DB_USER:-temporal}"
TEMPORAL_PASS="${TEMPORAL_DB_PASSWORD:-temporal}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER ${TEMPORAL_USER} WITH PASSWORD '${TEMPORAL_PASS}' CREATEDB;
    CREATE DATABASE temporal OWNER ${TEMPORAL_USER};
    CREATE DATABASE temporal_visibility OWNER ${TEMPORAL_USER};
EOSQL

# PostgreSQL 16+ requires explicit schema permissions
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "temporal" <<-EOSQL
    GRANT ALL ON SCHEMA public TO ${TEMPORAL_USER};
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "temporal_visibility" <<-EOSQL
    GRANT ALL ON SCHEMA public TO ${TEMPORAL_USER};
EOSQL

echo "Temporal databases initialized for user: ${TEMPORAL_USER}"
