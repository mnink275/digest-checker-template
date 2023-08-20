DROP SCHEMA IF EXISTS auth_schema CASCADE;

CREATE SCHEMA IF NOT EXISTS auth_schema;

CREATE TABLE IF NOT EXISTS auth_schema.users (
    username TEXT NOT NULL,
    nonce TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    nonce_count integer NOT NULL DEFAULT 0,
    ha1 TEXT NOT NULL,
    PRIMARY KEY(username)
);