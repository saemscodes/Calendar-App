-- ═══════════════════════════════════════════════════════════
--  SafeTrack / Calendar — Initial Schema + RLS
--  Supabase Postgres Migration 001
-- ═══════════════════════════════════════════════════════════

-- Enable needed extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────────
--  USERS
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username        TEXT UNIQUE NOT NULL,
  display_name    TEXT,
  phone           TEXT UNIQUE,
  npub            TEXT UNIQUE,           -- Nostr public key bech32, plaintext
  avatar_url      TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  DEVICE PINS  (Path A — 4-digit, device-bound)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS device_pins (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_fp       TEXT NOT NULL,          -- device fingerprint (browser/app generated)
  pin_hash        TEXT NOT NULL,          -- bcrypt hash of 4-digit PIN
  attempt_count   INTEGER DEFAULT 0,
  locked_until    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (user_id, device_fp)
);

-- ─────────────────────────────────────────────────────────
--  PENDING OTPs  (Path B — 6-digit real OTP)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pending_otps (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  otp_hash        TEXT NOT NULL,          -- bcrypt hash of 6-digit OTP
  purpose         TEXT NOT NULL DEFAULT 'login', -- login | device_add | account_recovery
  expires_at      TIMESTAMPTZ NOT NULL,
  used            BOOLEAN DEFAULT FALSE,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  NOSTR CREDENTIALS  (Path C — local key custody)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS nostr_credentials (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  npub            TEXT NOT NULL UNIQUE,   -- bech32 public key, plaintext
  auth_method     TEXT NOT NULL DEFAULT 'local', -- local | nip46
  nip46_relay     TEXT,                   -- relay URL for NIP-46 external signers
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  NOSTR CHALLENGES  (server-issued nonces for C1 & C2)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS nostr_challenges (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nonce           TEXT NOT NULL UNIQUE,   -- random single-use challenge string
  npub            TEXT NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  used            BOOLEAN DEFAULT FALSE,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  USER SETTINGS
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_settings (
  user_id                 UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  ping_mode               TEXT DEFAULT 'MEDIUM',
  adaptive_ping_enabled   BOOLEAN DEFAULT FALSE,
  custom_ping_interval_sec INTEGER,
  location_sharing_enabled BOOLEAN DEFAULT TRUE,
  retention_days          INTEGER DEFAULT 30,
  sos_mode                TEXT DEFAULT 'SILENT_ALERT',
  sos_group_id            UUID,
  created_at              TIMESTAMPTZ DEFAULT NOW(),
  updated_at              TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  CONTACT LINKS  (mutual opt-in)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS contact_links (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id_a       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_id_b       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  initiated_by    UUID NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending', -- pending | accepted | revoked
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (user_id_a, user_id_b),
  CHECK (user_id_a <> user_id_b)
);

-- ─────────────────────────────────────────────────────────
--  CONTACT GROUPS
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS contact_groups (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS contact_group_members (
  group_id        UUID NOT NULL REFERENCES contact_groups(id) ON DELETE CASCADE,
  linked_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, linked_user_id)
);

-- ─────────────────────────────────────────────────────────
--  CURRENT LOCATION  (always-retained last-known position)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS current_location (
  user_id         UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  lat             DOUBLE PRECISION NOT NULL,
  lng             DOUBLE PRECISION NOT NULL,
  accuracy        DOUBLE PRECISION,
  altitude        DOUBLE PRECISION,
  speed           DOUBLE PRECISION,
  bearing         DOUBLE PRECISION,
  battery_pct     INTEGER,
  source          TEXT NOT NULL DEFAULT 'NATIVE_GPS',
  ping_mechanism  TEXT,
  tracker_tag_id  UUID,
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  LOCATION HISTORY  (audit trail, subject to retention)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS location_history (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  lat             DOUBLE PRECISION NOT NULL,
  lng             DOUBLE PRECISION NOT NULL,
  accuracy        DOUBLE PRECISION,
  altitude        DOUBLE PRECISION,
  speed           DOUBLE PRECISION,
  bearing         DOUBLE PRECISION,
  battery_pct     INTEGER,
  source          TEXT NOT NULL,
  ping_mechanism  TEXT,
  tracker_tag_id  UUID,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_location_history_user ON location_history(user_id, created_at DESC);

-- ─────────────────────────────────────────────────────────
--  TRACKER TAGS  (BLE beacon management)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tracker_tags (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label           TEXT NOT NULL,
  ble_uuid        TEXT NOT NULL,
  last_seen_lat   DOUBLE PRECISION,
  last_seen_lng   DOUBLE PRECISION,
  last_seen_at    TIMESTAMPTZ,
  battery_pct     INTEGER,
  last_seen_address TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  SOS EVENTS
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sos_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  triggered_by    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  lat             DOUBLE PRECISION,
  lng             DOUBLE PRECISION,
  mode            TEXT NOT NULL DEFAULT 'SILENT_ALERT',
  group_id        UUID REFERENCES contact_groups(id),
  resolved_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sos_notifications (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sos_event_id    UUID NOT NULL REFERENCES sos_events(id) ON DELETE CASCADE,
  notified_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status          TEXT NOT NULL DEFAULT 'SENT',   -- SENT | DELIVERED | SEEN | ON_MY_WAY
  ack_message     TEXT,
  ack_at          TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  REMOTE PINGS
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS remote_pings (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  from_user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status          TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING | DELIVERED | EXPIRED
  responded_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  CALENDAR EVENTS  (decoy functional calendar)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS calendar_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title           TEXT NOT NULL,
  description     TEXT,
  start_at        TIMESTAMPTZ NOT NULL,
  end_at          TIMESTAMPTZ,
  all_day         BOOLEAN DEFAULT FALSE,
  color           TEXT DEFAULT '#007AFF',
  location        TEXT,
  recurrence      TEXT,   -- ical RRULE string
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_calendar_events_user ON calendar_events(user_id, start_at);

-- ─────────────────────────────────────────────────────────
--  ROW LEVEL SECURITY POLICIES
-- ─────────────────────────────────────────────────────────
ALTER TABLE users                ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_pins          ENABLE ROW LEVEL SECURITY;
ALTER TABLE pending_otps         ENABLE ROW LEVEL SECURITY;
ALTER TABLE nostr_credentials    ENABLE ROW LEVEL SECURITY;
ALTER TABLE nostr_challenges     ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_settings        ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_links        ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_groups       ENABLE ROW LEVEL SECURITY;
ALTER TABLE contact_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE current_location     ENABLE ROW LEVEL SECURITY;
ALTER TABLE location_history     ENABLE ROW LEVEL SECURITY;
ALTER TABLE tracker_tags         ENABLE ROW LEVEL SECURITY;
ALTER TABLE sos_events           ENABLE ROW LEVEL SECURITY;
ALTER TABLE sos_notifications    ENABLE ROW LEVEL SECURITY;
ALTER TABLE remote_pings         ENABLE ROW LEVEL SECURITY;
ALTER TABLE calendar_events      ENABLE ROW LEVEL SECURITY;

-- Users: can only read/update their own row
CREATE POLICY users_self ON users
  USING (id = auth.uid());

-- Device pins: only accessible by owner
CREATE POLICY device_pins_owner ON device_pins
  USING (user_id = auth.uid());

-- User settings: only by owner
CREATE POLICY settings_owner ON user_settings
  USING (user_id = auth.uid());

-- Calendar events: only by owner
CREATE POLICY calendar_owner ON calendar_events
  USING (user_id = auth.uid());

-- Tracker tags: only by owner
CREATE POLICY tracker_owner ON tracker_tags
  USING (user_id = auth.uid());

-- Contact links: visible if you are either party
CREATE POLICY contact_links_party ON contact_links
  USING (user_id_a = auth.uid() OR user_id_b = auth.uid());

-- Current location: visible if ACCEPTED mutual link exists, or own row
CREATE POLICY current_location_contacts ON current_location
  USING (
    user_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM contact_links cl
      WHERE cl.status = 'accepted'
        AND (
          (cl.user_id_a = auth.uid() AND cl.user_id_b = current_location.user_id)
          OR (cl.user_id_b = auth.uid() AND cl.user_id_a = current_location.user_id)
        )
    )
  );

-- Location history: same as current_location
CREATE POLICY location_history_contacts ON location_history
  USING (
    user_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM contact_links cl
      WHERE cl.status = 'accepted'
        AND (
          (cl.user_id_a = auth.uid() AND cl.user_id_b = location_history.user_id)
          OR (cl.user_id_b = auth.uid() AND cl.user_id_a = location_history.user_id)
        )
    )
  );

-- SOS events: triggering user can see their own; notified contacts can see events they were notified about
CREATE POLICY sos_events_access ON sos_events
  USING (
    triggered_by = auth.uid()
    OR EXISTS (
      SELECT 1 FROM sos_notifications sn
      WHERE sn.sos_event_id = sos_events.id
        AND sn.notified_id = auth.uid()
    )
  );

CREATE POLICY sos_notifications_access ON sos_notifications
  USING (
    notified_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM sos_events se
      WHERE se.id = sos_notifications.sos_event_id
        AND se.triggered_by = auth.uid()
    )
  );

-- Remote pings: sender or receiver
CREATE POLICY remote_pings_access ON remote_pings
  USING (from_user_id = auth.uid() OR target_user_id = auth.uid());

-- Nostr credentials: read-only to owner (writes via service role in Edge Functions only)
CREATE POLICY nostr_creds_owner ON nostr_credentials
  FOR SELECT USING (user_id = auth.uid());

-- Groups / members: owner only
CREATE POLICY groups_owner ON contact_groups USING (owner_user_id = auth.uid());
CREATE POLICY group_members_owner ON contact_group_members
  USING (
    EXISTS (
      SELECT 1 FROM contact_groups cg
      WHERE cg.id = contact_group_members.group_id
        AND cg.owner_user_id = auth.uid()
    )
  );

-- ─────────────────────────────────────────────────────────
--  DATA RETENTION FUNCTION  (scheduled via pg_cron or Supabase Scheduled Functions)
-- ─────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION purge_old_location_history()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  DELETE FROM location_history lh
  USING user_settings us
  WHERE lh.user_id = us.user_id
    AND lh.created_at < NOW() - (us.retention_days || ' days')::INTERVAL;

  -- Purge expired OTPs
  DELETE FROM pending_otps WHERE expires_at < NOW();

  -- Purge used / expired nostr challenges
  DELETE FROM nostr_challenges WHERE expires_at < NOW() OR used = TRUE;
END;
$$;
