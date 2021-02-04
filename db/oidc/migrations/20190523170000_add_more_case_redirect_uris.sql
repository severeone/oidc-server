-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

INSERT INTO client_redirect_uris(id, redirect_uri) VALUES ('oidc-backend', 'http://localhost:3000/signup-complete');

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DELETE FROM client_redirect_uris WHERE id = 'oidc-backend' AND redirect_uri = 'http://localhost:3000/signup-complete';
