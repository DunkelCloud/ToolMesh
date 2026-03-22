-- Temporal user with full privileges (needs CREATEDB for auto-setup)
CREATE USER temporal WITH PASSWORD 'temporal' CREATEDB;

-- Create databases for Temporal
CREATE DATABASE temporal OWNER temporal;
CREATE DATABASE temporal_visibility OWNER temporal;

-- PostgreSQL 16+ requires explicit schema permissions
\c temporal
GRANT ALL ON SCHEMA public TO temporal;
\c temporal_visibility
GRANT ALL ON SCHEMA public TO temporal;

-- Note: OpenFGA uses MySQL (see docker-compose.yml).
-- The MySQL database and user are created automatically via
-- MYSQL_DATABASE / MYSQL_USER environment variables.
