-- SafeTrack — Public Schema Reset Migration
-- Run this in the Supabase SQL Editor (or via Supabase CLI migrate)
-- to clear only the public schema tables before running `prisma db push`.
--
-- This is SAFE to run on a fresh Supabase project with no real data.
-- It only touches the `public` schema — Supabase system schemas are untouched.

-- ─── Step 1: Drop all public tables in dependency order ──────────────────────
DROP TABLE IF EXISTS public.seed_phrase_recovery CASCADE;
DROP TABLE IF EXISTS public.nostr_challenges CASCADE;
DROP TABLE IF EXISTS public.pending_otps CASCADE;
DROP TABLE IF EXISTS public.location_history CASCADE;
DROP TABLE IF EXISTS public.current_location CASCADE;
DROP TABLE IF EXISTS public.sos_notifications CASCADE;
DROP TABLE IF EXISTS public.sos_events CASCADE;
DROP TABLE IF EXISTS public.remote_pings CASCADE;
DROP TABLE IF EXISTS public.contact_group_members CASCADE;
DROP TABLE IF EXISTS public.contact_groups CASCADE;
DROP TABLE IF EXISTS public.contact_links CASCADE;
DROP TABLE IF EXISTS public.tracker_tags CASCADE;
DROP TABLE IF EXISTS public.refresh_tokens CASCADE;
DROP TABLE IF EXISTS public.user_settings CASCADE;
DROP TABLE IF EXISTS public.users CASCADE;
DROP TABLE IF EXISTS public."_prisma_migrations" CASCADE;

-- ─── Step 2: Drop all public types (Prisma will re-create them) ──────────────
DROP TYPE IF EXISTS public."ContactStatus" CASCADE;
DROP TYPE IF EXISTS public."LocationSource" CASCADE;
DROP TYPE IF EXISTS public."PingMechanism" CASCADE;
DROP TYPE IF EXISTS public."PingMode" CASCADE;
DROP TYPE IF EXISTS public."PingStatus" CASCADE;
DROP TYPE IF EXISTS public."SosAckStatus" CASCADE;
DROP TYPE IF EXISTS public."SosMode" CASCADE;

-- ─── Step 3: Drop any stale event triggers (from backup.sql rls_auto_enable) ─
DROP EVENT TRIGGER IF EXISTS rls_auto_enable_trigger CASCADE;

-- ─── Done. Run `npx prisma db push --accept-data-loss` after this. ────────────
SELECT 'SafeTrack public schema cleared. Ready for Prisma db push.' AS status;
