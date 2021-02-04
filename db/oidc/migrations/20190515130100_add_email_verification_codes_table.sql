-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Email verification codes
CREATE TABLE email_verification_codes (
    code  VARCHAR(60) NOT NULL PRIMARY KEY,
    email VARCHAR(60) NOT NULL
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE email_verification_codes;
