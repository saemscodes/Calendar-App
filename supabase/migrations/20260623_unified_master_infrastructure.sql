-- ════════════════════════════════════════════════════════
-- UNIFIED MASTER INFRASTRUCTURE MIGRATION
-- ════════════════════════════════════════════════════════

-- 1. HARDENED USERS EXTENSION
ALTER TABLE IF EXISTS public.users 
ADD COLUMN IF NOT EXISTS ancestry_path TEXT, -- Npub-based tree
ADD COLUMN IF NOT EXISTS invite_quota INTEGER DEFAULT 3,
ADD COLUMN IF NOT EXISTS metadata_hash TEXT; -- Hash of last verified device context

-- 2. SECURE DEVICE REGISTRY
CREATE TABLE IF NOT EXISTS public.user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    fingerprint_hash TEXT NOT NULL,
    metadata_json JSONB DEFAULT '{}'::jsonb,
    is_trusted BOOLEAN DEFAULT TRUE,
    last_active TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(user_id, fingerprint_hash)
);

-- 3. HARDWARE TRACKER MESH
CREATE TABLE IF NOT EXISTS public.tracker_tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    last_lat DOUBLE PRECISION,
    last_lng DOUBLE PRECISION,
    battery_level INTEGER,
    last_seen TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 4. VOUCH SYSTEM (PENDING OTPS)
CREATE TABLE IF NOT EXISTS public.pending_otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Safeguard: Ensure columns exist if table was previously created
ALTER TABLE public.pending_otps 
ADD COLUMN IF NOT EXISTS inviter_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS first_touched_at TIMESTAMPTZ;

-- 5. AIRTIGHT RLS POLICIES
ALTER TABLE public.user_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tracker_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pending_otps ENABLE ROW LEVEL SECURITY;

-- Device Policy (Owner only)
DO $$ BEGIN
    CREATE POLICY "Devices owner access" ON public.user_devices
    FOR ALL USING (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Tracker Policy (Owner only)
DO $$ BEGIN
    CREATE POLICY "Trackers owner access" ON public.tracker_tags
    FOR ALL USING (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- OTP Policy (Inviter can see their own codes)
DO $$ BEGIN
    CREATE POLICY "Inviter see own codes" ON public.pending_otps
    FOR SELECT USING (auth.uid() = inviter_id);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- 6. OPTIMIZED RPC BOOTSTRAP (The "One-Trip" Loader)
CREATE OR REPLACE FUNCTION public.get_safe_track_bootstrap()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    result JSONB;
    v_user_id UUID := auth.uid();
BEGIN
    SELECT jsonb_build_object(
        'profile', (SELECT row_to_json(u) FROM public.users u WHERE u.id = v_user_id),
        'contacts', (
            SELECT COALESCE(jsonb_agg(row_to_json(c)), '[]'::jsonb)
            FROM (
                SELECT c.*, u.username, u.display_name, u.npub 
                FROM public.contacts c
                JOIN public.users u ON (c.friend_id = u.id)
                WHERE c.user_id = v_user_id
            ) c
        ),
        'trackers', (
            SELECT COALESCE(jsonb_agg(row_to_json(t)), '[]'::jsonb)
            FROM public.tracker_tags t WHERE t.user_id = v_user_id
        ),
        'devices', (
            SELECT COALESCE(jsonb_agg(row_to_json(d)), '[]'::jsonb)
            FROM public.user_devices d WHERE d.user_id = v_user_id
        )
    ) INTO result;
    
    RETURN result;
END;
$$;
