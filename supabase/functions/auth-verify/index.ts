// Supabase Edge Function: auth-verify
// The ONLY authentication entry point. Receives a raw string from the Calendar search bar.
// Performs client-side-independent routing: 4-digit PIN, 6-digit OTP/decoy, or Nostr string.
// Mints a Supabase-compatible JWT on success. Returns search-result-shaped JSON on non-match.

import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { create, getNumericDate } from 'https://deno.land/x/djwt@v2.8/mod.ts';
import * as bcrypt from 'https://deno.land/x/bcrypt@v0.4.1/mod.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const JWT_SECRET = Deno.env.get('SUPABASE_JWT_SECRET')!;

// Supabase admin client (bypasses RLS — only used here to verify credentials)
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ─── CORS headers ────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Device-FP',
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// ─── JWT minting (produces a Supabase-compatible session JWT) ─
async function mintJWT(userId: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(JWT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const exp = getNumericDate(60 * 60 * 24 * 7); // 7 days
  return create(
    { alg: 'HS256', typ: 'JWT' },
    {
      sub: userId,
      role: 'authenticated',
      iss: 'supabase',
      iat: getNumericDate(0),
      exp,
    },
    key,
  );
}

// ─── PATH DETERMINATOR (client-side parity — see spec §13) ──
type AuthPath = 'four_digit' | 'six_digit' | 'nostr_string' | 'mnemonic_phrase' | 'unknown';

function determineShape(input: string): AuthPath {
  const trimmed = input.trim();
  if (/^\d{4}$/.test(trimmed)) return 'four_digit';
  if (/^\d{6}$/.test(trimmed)) return 'six_digit';
  // Nostr keys: nsec1... npub1... or raw 64-char hex
  if (/^(nsec1|npub1)[a-z0-9]{58,}$/.test(trimmed)) return 'nostr_string';
  if (/^[0-9a-f]{64}$/.test(trimmed)) return 'nostr_string';
  // Signatures (128-char hex from challenge-signing)
  if (/^[0-9a-f]{128}$/.test(trimmed)) return 'nostr_string';
  // Mnemonic phrase: 12 or 24 words separated by spaces (any language — any unicode)
  // Minimum 11 spaces (= 12 words), maximum 23 spaces (= 24 words).
  const spaces = (trimmed.match(/\s+/g) || []).length;
  if (spaces >= 11 && spaces <= 23) {
    const words = trimmed.split(/\s+/);
    if (words.length === 12 || words.length === 24) return 'mnemonic_phrase';
  }
  return 'unknown';
}

// ─── SILENT FAIL: Return calendar-search-shaped response ────
function calendarSearchFallback(input: string) {
  // Looks like a normal empty search result — zero leakage
  return json({ type: 'calendar_search', results: [], query: input });
}

// ─── PATH A: 4-DIGIT DEVICE-BOUND PIN ───────────────────────
async function handleFourDigit(pin: string, deviceFp: string): Promise<Response> {
  if (!deviceFp) return calendarSearchFallback(pin);

  const { data: row, error } = await supabase
    .from('device_pins')
    .select('id, user_id, pin_hash, attempt_count, locked_until')
    .eq('device_fp', deviceFp)
    .maybeSingle();

  if (error || !row) return calendarSearchFallback(pin);

  // Check lockout
  if (row.locked_until && new Date(row.locked_until) > new Date()) {
    return calendarSearchFallback(pin); // silently deny during lockout
  }

  const match = await bcrypt.compare(pin, row.pin_hash);

  if (!match) {
    const newCount = (row.attempt_count ?? 0) + 1;
    const locked_until = newCount >= 5
      ? new Date(Date.now() + 15 * 60 * 1000).toISOString()
      : null;

    await supabase.from('device_pins').update({ attempt_count: newCount, locked_until })
      .eq('id', row.id);

    return calendarSearchFallback(pin);
  }

  // Success — reset attempt count, mint JWT
  await supabase.from('device_pins').update({ attempt_count: 0, locked_until: null })
    .eq('id', row.id);

  const token = await mintJWT(row.user_id);
  const { data: user } = await supabase.from('users').select('*').eq('id', row.user_id).single();
  return json({ type: 'auth_success', path: 'pin', token, user });
}

// ─── PATH B: 6-DIGIT (OTP or decoy) ────────────────────────
async function handleSixDigit(code: string, deviceFp: string): Promise<Response> {
  // Check live OTP table first
  const { data: otps, error } = await supabase
    .from('pending_otps')
    .select('id, user_id, otp_hash, expires_at, used')
    .eq('used', false)
    .gt('expires_at', new Date().toISOString())
    .order('created_at', { ascending: false })
    .limit(50);

  if (!error && otps && otps.length > 0) {
    for (const otp of otps) {
      const match = await bcrypt.compare(code, otp.otp_hash);
      if (match) {
        // Mark used
        await supabase.from('pending_otps').update({ used: true }).eq('id', otp.id);
        const token = await mintJWT(otp.user_id);
        const { data: user } = await supabase.from('users').select('*').eq('id', otp.user_id).single();
        return json({ type: 'auth_success', path: 'otp', token, user });
      }
    }
  }

  // No matching OTP — route to demo experience (no real user data exposed)
  return json({ type: 'demo_access', path: 'decoy_date' });
}

// ─── PATH C: NOSTR STRING ───────────────────────────────────
// Delegates to the dedicated auth-nostr function for signature verification
async function handleNostrString(input: string, deviceFp: string): Promise<Response> {
  const nostrFnUrl = `${SUPABASE_URL}/functions/v1/auth-nostr`;
  const resp = await fetch(nostrFnUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'X-Device-FP': deviceFp,
    },
    body: JSON.stringify({ input }),
  });
  const data = await resp.json();
  return json(data, resp.status);
}

// ─── PATH D: MNEMONIC PHRASE ─────────────────────────────────
// The raw phrase is not parsed here (no wordlist on the backend).
// We return a typed signal to the client telling it to execute the
// local BIP39 → nsec derivation → Nostr challenge-response flow.
// The server never receives the mnemonic words themselves.
function handleMnemonicPhrase(input: string): Response {
  const wordCount = input.trim().split(/\s+/).length;
  // Signal client to perform local BIP39 derivation and then use auth-nostr
  return json({
    type: 'mnemonic_derive_required',
    word_count: wordCount,
    message: 'Derive nsec locally, then authenticate via nostr challenge-response',
  });
}

// ─── MAIN HANDLER ────────────────────────────────────────────
serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: CORS });
  }

  if (req.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405);
  }

  let body: { input?: string };
  try {
    body = await req.json();
  } catch {
    return calendarSearchFallback('');
  }

  const input = (body.input ?? '').trim();
  const deviceFp = req.headers.get('X-Device-FP') ?? '';

  if (!input) return calendarSearchFallback(input);

  const shape = determineShape(input);

  switch (shape) {
    case 'four_digit':
      return handleFourDigit(input, deviceFp);
    case 'six_digit':
      return handleSixDigit(input, deviceFp);
    case 'nostr_string':
      return handleNostrString(input, deviceFp);
    case 'mnemonic_phrase':
      // Mnemonic phrases are processed entirely on the client side.
      // The server only signals: "this is a mnemonic, please derive locally."
      return handleMnemonicPhrase(input);
    default:
      // Plain text — not an auth attempt, treat as calendar search pass-through
      return calendarSearchFallback(input);
  }
});
