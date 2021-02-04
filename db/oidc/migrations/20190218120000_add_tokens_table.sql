-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Access and refresh tokens
CREATE TABLE tokens (
    refresh_token           VARCHAR(60) NOT NULL PRIMARY KEY,
    encrypted_access_token  TEXT NOT NULL UNIQUE,
    client_id               VARCHAR(60) NOT NULL REFERENCES clients (id)
);

CREATE TABLE tokens_life_time (
    user_type               INTEGER NOT NULL REFERENCES user_account_types (type),
    client_id               VARCHAR(60) NOT NULL REFERENCES clients (id),
    access_token_life_time  INTEGER NOT NULL, -- in seconds
    auth_code_life_time     INTEGER NOT NULL, -- in seconds
    PRIMARY KEY (user_type, client_id)
);

INSERT INTO clients(id, secret, name) VALUES ('example-backend', crypt('ExAmPlE$221', gen_salt('bf', 10)), 'Example.com');

INSERT INTO tokens_life_time(user_type, client_id, access_token_life_time, auth_code_life_time)
    VALUES (1, 'example-backend', 86400, 600);
INSERT INTO tokens_life_time(user_type, client_id, access_token_life_time, auth_code_life_time)
    VALUES (2, 'example-backend', 86400, 600);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DELETE FROM tokens_life_time WHERE user_type = 1 AND client_id = 'example-backend';
DELETE FROM tokens_life_time WHERE user_type = 2 AND client_id = 'example-backend';

DELETE FROM clients WHERE id = 'example-backend';

DROP TABLE tokens_life_time;
DROP TABLE tokens;
