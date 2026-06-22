-- SafeTrack STRICT MODE: SMS Hardening Migration
-- 1. Table for multi-part SMS fragment reassembly
CREATE TABLE IF NOT EXISTS sms_fragments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_hash TEXT NOT NULL, -- SHA-256 of phone number
  total_parts INTEGER NOT NULL,
  part_number INTEGER NOT NULL,
  payload TEXT NOT NULL,
  received_at TIMESTAMPTZ DEFAULT now(),
  assembled BOOLEAN DEFAULT false
);

-- Index for fast reassembly lookups
CREATE INDEX IF NOT EXISTS idx_sms_fragments_sender_hash ON sms_fragments(sender_hash);

-- 2. Table for SMS broadcast audit logs
CREATE TABLE IF NOT EXISTS sms_broadcast_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id_prefix TEXT NOT NULL,
  sender_hash TEXT NOT NULL,
  relay_results JSONB NOT NULL, -- Status per relay
  status TEXT NOT NULL, -- CONFIRMED, PARTIAL, FAILED
  created_at TIMESTAMPTZ DEFAULT now()
);

-- 3. Cleanup Policy: Delete stale fragments after 10 minutes
-- Note: Requires pg_cron to be enabled in Supabase dashboard
-- SELECT cron.schedule('sms-fragment-cleanup', '*/10 * * * *', 'DELETE FROM sms_fragments WHERE received_at < now() - interval ''10 minutes''');
