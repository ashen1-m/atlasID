-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────
--  Identity_Record  (PDF: identity_id PK, full_name,
--  date_of_birth, enrollment_date, status ENUM)
-- ─────────────────────────────────────────────────────
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    did             VARCHAR(255) UNIQUE NOT NULL,
    name            VARCHAR(255) NOT NULL,
    date_of_birth   DATE,
    enrollment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status          VARCHAR(20) DEFAULT 'Active'
                    CHECK (status IN ('Active', 'Revoked')),
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────
--  PublicKey_Collection  (PDF: issuer_did, public_key_base58, last_synced)
-- ─────────────────────────────────────────────────────
CREATE TABLE public_keys (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    issuer_did  VARCHAR(255),
    key_value   TEXT NOT NULL,
    last_synced TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────
--  VerifiableCredential_Collection
--  (PDF: type Array, credentialSubject JSON, proof Ed25519)
-- ─────────────────────────────────────────────────────
CREATE TABLE credentials (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
    issuer_did VARCHAR(255),
    type       VARCHAR(100) NOT NULL,
    payload    JSONB NOT NULL,
    signature  TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────
--  Aid_Entitlement  — NEW — exact match to PDF:
--  entitlement_id PK, identity_id FK, aid_type VARCHAR,
--  value DECIMAL, issued_at TIMESTAMP
--  + added: currency, period dates, status, notes
-- ─────────────────────────────────────────────────────
CREATE TABLE aid_entitlements (
    entitlement_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id    UUID REFERENCES users(id) ON DELETE CASCADE,
    aid_type       VARCHAR(100) NOT NULL,
    value          DECIMAL(12,2) NOT NULL DEFAULT 0,
    currency       VARCHAR(10)   NOT NULL DEFAULT 'USD',
    period_start   DATE,
    period_end     DATE,
    status         VARCHAR(20) DEFAULT 'Active'
                   CHECK (status IN ('Active','Suspended','Exhausted','Expired')),
    issued_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes          TEXT
);

-- ─────────────────────────────────────────────────────
--  Audit Logs
-- ─────────────────────────────────────────────────────
CREATE TABLE logs (
    id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action    VARCHAR(255) NOT NULL,
    details   JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_credentials_user     ON credentials(user_id);
CREATE INDEX idx_public_keys_user     ON public_keys(user_id);
CREATE INDEX idx_entitlements_identity ON aid_entitlements(identity_id);
CREATE INDEX idx_entitlements_status   ON aid_entitlements(status);
CREATE INDEX idx_logs_ts              ON logs(timestamp DESC);
