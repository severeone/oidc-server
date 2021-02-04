-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

INSERT INTO client_redirect_uris(id, redirect_uri) VALUES ('example-backend', 'https://example.com/signup-complete');

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DELETE FROM client_redirect_uris WHERE id = 'example-backend' AND redirect_uri = 'https://example.com/signup-complete';