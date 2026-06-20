// Supabase Edge Function: auth-seed
// Handles Path D authentication — BIP39 mnemonic phrase recovery.
// The raw phrase NEVER reaches this function. The client:
//   1. Derives the npub from the mnemonic locally.
//   2. Requests a Nostr challenge for that npub.
//   3. Signs the challenge locally using the derived nsec.
//   4. Sends only (npub, nonce, sig, entropy_fingerprint) to this function.
// This function verifies the Schnorr signature, then looks up the account
// by npub and cross-checks the entropy_fingerprint if one was stored.
// On success it mints and returns a Supabase-compatible JWT.
// On failure it always returns the calendarSearchFallback — zero leakage.

import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { create, getNumericDate } from 'https://deno.land/x/djwt@v2.8/mod.ts';
import * as bcrypt from 'https://deno.land/x/bcrypt@v0.4.1/mod.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const JWT_SECRET = Deno.env.get('SUPABASE_JWT_SECRET')!;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Device-FP',
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// Always return this on any failure path — indistinguishable from a calendar search
function silentFail() {
  return json({ type: 'calendar_search', results: [] });
}

async function mintJWT(userId: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(JWT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return create(
    { alg: 'HS256', typ: 'JWT' },
    {
      sub: userId,
      role: 'authenticated',
      iss: 'supabase',
      iat: getNumericDate(0),
      exp: getNumericDate(60 * 60 * 24 * 7), // 7 days
    },
    key,
  );
}

// ─── Schnorr signature verification via @noble/curves ────────────────────────
async function verifySchnorrSignature(
  pubkeyHex: string,
  nonce: string,
  sigHex: string,
): Promise<boolean> {
  try {
    const { schnorr } = await import('https://esm.sh/@noble/curves@1.2.0/secp256k1');
    const msgBytes = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(nonce)),
    );
    return schnorr.verify(sigHex, msgBytes, pubkeyHex);
  } catch {
    return false;
  }
}

// ─── bech32 npub → raw hex pubkey ────────────────────────────────────────────
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GENERATOR[i];
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function npubToHex(npub: string): string | null {
  try {
    const str = npub.toLowerCase();
    const pos = str.lastIndexOf('1');
    if (pos < 1 || pos + 7 > str.length) return null;
    const hrp = str.slice(0, pos);
    if (hrp !== 'npub') return null;
    const data: number[] = [];
    for (let i = pos + 1; i < str.length; i++) {
      const v = CHARSET.indexOf(str[i]);
      if (v < 0) return null;
      data.push(v);
    }
    if (bech32Polymod([...bech32HrpExpand(hrp), ...data]) !== 1) return null;
    const words = data.slice(0, -6);
    const bytes: number[] = [];
    let value = 0, bits = 0;
    for (const w of words) {
      value = (value << 5) | w;
      bits += 5;
      while (bits >= 8) {
        bits -= 8;
        bytes.push((value >> bits) & 0xff);
      }
    }
    if (bytes.length !== 32) return null;
    return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return null;
  }
}

// ─── Main handler ─────────────────────────────────────────────────────────────
serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
  if (req.method !== 'POST') return silentFail();

  let body: Record<string, string>;
  try {
    body = await req.json();
  } catch {
    return silentFail();
  }

  const { npub, nonce, sig, entropy_fingerprint, action } = body;

  // ── Step 1: Verify the Schnorr signature ─────────────────────────────────
  if (!npub || !nonce || !sig) return silentFail();

  // Fetch the original challenge
  const { data: challenge, error: challengeErr } = await supabase
    .from('nostr_challenges')
    .select('id, npub, expires_at, used')
    .eq('nonce', nonce)
    .eq('npub', npub)
    .eq('used', false)
    .maybeSingle();

  if (challengeErr || !challenge) return silentFail();
  if (new Date(challenge.expires_at) < new Date()) return silentFail();

  // Mark used immediately to prevent replay
  await supabase.from('nostr_challenges').update({ used: true }).eq('id', challenge.id);

  // Derive pubkeyHex
  let pubkeyHex: string | null = null;
  if (npub.startsWith('npub1')) {
    pubkeyHex = npubToHex(npub);
  } else if (/^[0-9a-f]{64}$/.test(npub)) {
    pubkeyHex = npub;
  }
  if (!pubkeyHex) return silentFail();

  const valid = await verifySchnorrSignature(pubkeyHex, nonce, sig);
  if (!valid) return silentFail();

  // ── Step 2: Find account by npub ─────────────────────────────────────────
  const { data: nc } = await supabase
    .from('nostr_credentials')
    .select('user_id')
    .eq('npub', npub)
    .maybeSingle();

  if (!nc) return silentFail(); // npub not registered — seed phrase can't recover an unknown account

  // ── Step 3: Cross-check entropy_fingerprint if stored ────────────────────
  if (entropy_fingerprint) {
    const { data: seedRow } = await supabase
      .from('seed_phrase_recovery')
      .select('entropy_fingerprint')
      .eq('user_id', nc.user_id)
      .maybeSingle();

    // If the account has a stored fingerprint and the provided one doesn't match → silent fail
    if (seedRow?.entropy_fingerprint && seedRow.entropy_fingerprint !== entropy_fingerprint) {
      return silentFail();
    }
  }

  // ── Step 4: Fetch user and mint JWT ──────────────────────────────────────
  const { data: user } = await supabase
    .from('users')
    .select('id, username, display_name, phone, npub')
    .eq('id', nc.user_id)
    .single();

  if (!user) return silentFail();

  const token = await mintJWT(user.id);
  return json({ type: 'auth_success', path: 'seed_recovery', token, user });
});
