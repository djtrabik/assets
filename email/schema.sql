-- Kalkulačka E-liquidů 2.5 – online databáze PostgreSQL
-- Každý záznam uživatelských dat musí obsahovat owner_id.
CREATE TABLE IF NOT EXISTS app_users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    preferred_language TEXT NOT NULL DEFAULT 'CS'
        CHECK (preferred_language IN ('CS','EN','DE','FR','PL','ES')),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    auth_version INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_preferences (
    owner_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (owner_id, key)
);

-- Základní online datové tabulky. Rozšiřují se migracemi; nesdílejí se
-- s lokální SQLite databází HOST režimu.
CREATE TABLE IF NOT EXISTS materials (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    stock DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (stock >= 0),
    minimum DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (minimum >= 0),
    unit_price DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (unit_price >= 0),
    strength DOUBLE PRECISION NOT NULL DEFAULT 0,
    vg DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, name)
);
CREATE INDEX IF NOT EXISTS ix_materials_owner ON materials(owner_id);

CREATE TABLE IF NOT EXISTS recipes (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_recipes_owner ON recipes(owner_id);

CREATE TABLE IF NOT EXISTS batches (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    cost DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (cost >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_batches_owner ON batches(owner_id);


-- Auditní kniha skladových pohybů. Záznamy jsou navázány na vlastníka i materiál.
CREATE TABLE IF NOT EXISTS stock_movements (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    material_id BIGINT NOT NULL REFERENCES materials(id) ON DELETE RESTRICT,
    movement_type TEXT NOT NULL CHECK (movement_type IN ('IN','OUT','ADJUSTMENT')),
    quantity DOUBLE PRECISION NOT NULL CHECK (quantity > 0),
    stock_after DOUBLE PRECISION NOT NULL CHECK (stock_after >= 0),
    note TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_stock_movements_owner_created
    ON stock_movements(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_stock_movements_material_created
    ON stock_movements(owner_id, material_id, created_at DESC);


-- Jednorázové e-mailové ověřovací a resetovací kódy. Ukládá se pouze SHA-256 hash.
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE app_users ADD COLUMN IF NOT EXISTS auth_version INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS account_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('verify_email','password_reset','email_change')),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE account_tokens ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE account_tokens ADD COLUMN IF NOT EXISTS pending_email TEXT;
ALTER TABLE account_tokens DROP CONSTRAINT IF EXISTS account_tokens_purpose_check;
ALTER TABLE account_tokens ADD CONSTRAINT account_tokens_purpose_check CHECK (purpose IN ('verify_email','password_reset','email_change'));
CREATE INDEX IF NOT EXISTS ix_account_tokens_user_purpose ON account_tokens(user_id,purpose);
CREATE INDEX IF NOT EXISTS ix_account_tokens_expiry ON account_tokens(expires_at);


-- Kompletní synchronizační snímek lokálního zařízení; revize chrání před přepsáním změn.
CREATE TABLE IF NOT EXISTS sync_documents (
    owner_id BIGINT PRIMARY KEY REFERENCES app_users(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    payload JSONB NOT NULL,
    checksum TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sync_document_history (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL,
    payload JSONB NOT NULL,
    checksum TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, revision)
);
CREATE INDEX IF NOT EXISTS ix_sync_document_history_owner_created
    ON sync_document_history(owner_id, created_at DESC);
