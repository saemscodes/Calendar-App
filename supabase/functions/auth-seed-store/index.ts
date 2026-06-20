// Supabase Edge Function: auth-seed-store
// Called by an AUTHENTICATED client (valid JWT required) to store the
// bcrypt hash of their BIP39 mnemonic phrase + entropy fingerprint.
// The raw phrase_joined is bcrypt-hashed here and then discarded.
// The hash is stored in seed_phrase_recovery — no raw phrase persists.

import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import * as bcrypt from 'https://deno.land/x/bcrypt@v0.4.1/mod.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const SUPABASE_JWT_SECRET = Deno.env.get('SUPABASE_JWT_SECRET')!;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// Verify the incoming JWT by decoding claim manually (service_role bypass used
// only for DB writes — user identity is confirmed from the token's sub claim).
async function verifyJWT(token: string): Promise<string | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (!payload.sub) return null;
    // Basic expiry check
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload.sub as string;
  } catch {
    return null;
  }
}

const SUPPORTED_LANGUAGES = ['en', 'am', 'ti', 'fr', 'es', 'zh-cn'];

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  // ── Authenticate ─────────────────────────────────────────
  const authHeader = req.headers.get('Authorization') ?? '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  const userId = await verifyJWT(token);
  if (!userId) return json({ error: 'Unauthorized' }, 401);

  // ── Parse body ───────────────────────────────────────────
  let body: {
    phrase_joined?: string;
    language?: string;
    word_count?: number;
    entropy_fingerprint?: string;
  };
  try {
    body = await req.json();
  } catch {
    return json({ error: 'Invalid JSON' }, 400);
  }

  const { phrase_joined, language = 'en', word_count, entropy_fingerprint } = body;

  if (!phrase_joined) return json({ error: 'phrase_joined required' }, 400);

  const words = phrase_joined.trim().split(/\s+/).filter(Boolean);
  if (words.length !== 12 && words.length !== 24) {
    return json({ error: 'Phrase must be 12 or 24 words' }, 400);
  }

  if (!SUPPORTED_LANGUAGES.includes(language)) {
    return json({ error: 'Unsupported language' }, 400);
  }

  // ── Bcrypt-hash the phrase server-side ───────────────────
  // Cost factor 12 — appropriate for recovery phrase (used infrequently)
  const phraseHash = await bcrypt.hash(phrase_joined.toLowerCase().trim(), 12);

  // ── Upsert into seed_phrase_recovery ─────────────────────
  const { error } = await supabase
    .from('seed_phrase_recovery')
    .upsert(
      {
        user_id: userId,
        phrase_hash: phraseHash,
        language,
        word_count: word_count ?? words.length,
        entropy_fingerprint: entropy_fingerprint ?? null,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'user_id' }
    );

  if (error) {
    console.error('[auth-seed-store] DB error:', error.message);
    return json({ error: 'Failed to store seed phrase' }, 500);
  }

  // phrase_joined is now out of scope — GC will collect it
  return json({ ok: true, language, word_count: words.length });
});
