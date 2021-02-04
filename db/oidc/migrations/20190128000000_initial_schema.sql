-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- User account types
CREATE TABLE user_account_types (
    type          SERIAL PRIMARY KEY,
    description   TEXT
);

-- Registered users
CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    type          INTEGER NOT NULL REFERENCES user_account_types (type),
    email         TEXT NOT NULL UNIQUE,
    first_name    TEXT,
    last_name     TEXT,
    password      TEXT NOT NULL,
    created       TIMESTAMP NOT NULL,
    verified      BOOLEAN -- Denormalized, indicates that at least one email for this account is verified.
);

-- Registered clients
CREATE TABLE clients (
    id            VARCHAR(60) NOT NULL PRIMARY KEY,
    secret        TEXT NOT NULL,
    name          TEXT
);

-- Client redirection URIs
CREATE TABLE client_redirect_uris (
    id            VARCHAR(60) NOT NULL REFERENCES clients (id),
    redirect_uri  TEXT NOT NULL, -- URL that references a resource containing a Request Object
    UNIQUE (id, redirect_uri)
);

-- OpenID Connect ongoing sessions
CREATE TABLE auth_sessions (
    code          VARCHAR(60) NOT NULL PRIMARY KEY,
    client_id     VARCHAR(60) NOT NULL REFERENCES clients (id),
    user_id       INTEGER NOT NULL REFERENCES users (id),
    valid_till    TIMESTAMP NOT NULL,
    redirect_uri  TEXT NOT NULL,
    nonce         TEXT -- String value used to associate a Client session with an ID Token & to mitigate replay attacks
);

-- Initial data
INSERT INTO user_account_types(description) VALUES ('regular');
INSERT INTO user_account_types(description) VALUES ('admin');

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE auth_sessions;
DROP TABLE client_redirect_uris;
DROP TABLE clients;
DROP TABLE users;
DROP TABLE user_account_types;
