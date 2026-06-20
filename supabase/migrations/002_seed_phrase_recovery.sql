-- ═══════════════════════════════════════════════════════════
--  SafeTrack / Calendar — Migration 002
--  Seed Phrase Recovery + Nostr Challenges + Language Index
-- ═══════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────
--  NOSTR CHALLENGES  (Path C challenge/response)
--  NOTE: Some deployments may have this already via migration
--  001 — guard with IF NOT EXISTS on all objects.
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS nostr_challenges (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  nonce       TEXT NOT NULL UNIQUE,
  npub        TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  used        BOOLEAN DEFAULT FALSE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS nostr_challenges_npub_idx ON nostr_challenges (npub);
CREATE INDEX IF NOT EXISTS nostr_challenges_expires_idx ON nostr_challenges (expires_at);

-- ─────────────────────────────────────────────────────────
--  SEED PHRASE RECOVERY
--  Stores a bcrypt hash of the canonical (space-joined,
--  lowercase) mnemonic phrase. The raw phrase NEVER appears
--  in the database. The hash is used server-side to verify
--  recovery attempts only — it never travels to client.
--
--  Language field stores the BIP39 wordlist locale:
--    'en'      — English
--    'am'      — Amharic  (SafeTrack custom 2048-word list)
--    'ti'      — Tigrinya (SafeTrack custom 2048-word list)
--    'fr'      — French   (BIP39 standard)
--    'es'      — Spanish  (BIP39 standard)
--    'zh-cn'   — Chinese Simplified
--
--  entropy_fingerprint: first 8 hex chars of SHA256(entropy_bytes)
--  used only to confirm the recovered entropy matches — never
--  the full entropy nor the private key.
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS seed_phrase_recovery (
  id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  phrase_hash           TEXT NOT NULL,      -- bcrypt hash of canonical lowercased phrase
  language              TEXT NOT NULL DEFAULT 'en',
  word_count            INTEGER NOT NULL DEFAULT 12,  -- 12 or 24
  entropy_fingerprint   TEXT,               -- first 8 hex chars of SHA256(entropy)
  created_at            TIMESTAMPTZ DEFAULT NOW(),
  updated_at            TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (user_id)      -- one active seed per user; update to rotate
);

-- ─────────────────────────────────────────────────────────
--  CALENDAR EVENTS  (Supabase-side decoy calendar storage)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS calendar_events (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title       TEXT NOT NULL,
  description TEXT,
  start_at    TIMESTAMPTZ,
  end_at      TIMESTAMPTZ,
  all_day     BOOLEAN DEFAULT FALSE,
  location    TEXT,
  color       TEXT DEFAULT '#007AFF',
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS calendar_events_user_start_idx ON calendar_events (user_id, start_at);

-- ─────────────────────────────────────────────────────────
--  RLS POLICIES
-- ─────────────────────────────────────────────────────────

-- nostr_challenges: readable only by service role (Edge Functions)
ALTER TABLE nostr_challenges ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  CREATE POLICY nostr_challenges_service_only ON nostr_challenges
    USING (FALSE);          -- blocks all direct client access; service_role bypasses RLS
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- seed_phrase_recovery: no direct client access ever
ALTER TABLE seed_phrase_recovery ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  CREATE POLICY seed_phrase_no_client_access ON seed_phrase_recovery
    USING (FALSE);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- calendar_events: user sees only own rows
ALTER TABLE calendar_events ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  CREATE POLICY calendar_events_owner ON calendar_events
    USING (user_id = auth.uid()::UUID)
    WITH CHECK (user_id = auth.uid()::UUID);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ─────────────────────────────────────────────────────────
--  RETENTION: auto-expire old nostr_challenges
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION purge_expired_nostr_challenges()
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM nostr_challenges WHERE expires_at < NOW() - INTERVAL '1 hour';
END;
$$;
