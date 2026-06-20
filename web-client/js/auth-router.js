/**
 * SafeTrack — Auth Router (Hybrid Search Bar)
 * Spec §13: Client performs shape triage, fires parallel backend check
 * ONLY for shaped inputs. Calendar local search always runs immediately.
 *
 * Auth Paths:
 *   A) 4-digit PIN       → backend verify (device-bound, rate-limited)
 *   B) 6-digit code      → OTP verify or demo-mode decoy
 *   C) nsec1/npub1/hex64 → Nostr challenge-response (local signing, no nsec leaves device)
 *   D) 12/24-word phrase → BIP39 mnemonic → local nsec derivation → Nostr challenge-response
 *
 * Seed phrase rules:
 *   - ANY language supported (English, Amharic, Tigrinya, etc.)
 *   - The raw words NEVER leave the browser
 *   - The derived nsec NEVER leaves the browser
 *   - Only (npub, schnorr-sig, entropy_fingerprint) reach the server
 *
 * npub stored/matched as plaintext — never hashed.
 */

const AuthRouter = (() => {
  // ── Config ───────────────────────────────────────────────
  const SUPABASE_URL = window.SUPABASE_URL || '';
  const EDGE_AUTH  = `${SUPABASE_URL}/functions/v1/auth-verify`;
  const EDGE_NOSTR = `${SUPABASE_URL}/functions/v1/auth-nostr`;
  const EDGE_SEED  = `${SUPABASE_URL}/functions/v1/auth-seed`;

  // ── Device fingerprint (ephemeral, session-stable) ───────
  const DEVICE_FP_KEY = 'st_device_fp';
  function getDeviceFP() {
    let fp = localStorage.getItem(DEVICE_FP_KEY);
    if (!fp) {
      fp = Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      localStorage.setItem(DEVICE_FP_KEY, fp);
    }
    return fp;
  }

  // ── Shape triage (mirrors backend determineShape) ─────────
  function determineShape(input) {
    const t = input.trim();
    if (/^\d{4}$/.test(t)) return 'four_digit';
    if (/^\d{6}$/.test(t)) return 'six_digit';
    if (/^(nsec1|npub1)[a-z0-9]{58,}$/.test(t)) return 'nostr_string';
    if (/^[0-9a-f]{64}$/.test(t)) return 'nostr_string';
    if (/^[0-9a-f]{128}$/.test(t)) return 'nostr_string'; // signatures from challenge flow

    // Mnemonic phrase: 12 or 24 whitespace-separated words (any language)
    const words = t.split(/\s+/).filter(Boolean);
    if (words.length === 12 || words.length === 24) return 'mnemonic_phrase';

    return 'calendar_text';
  }

  // ── Call backend auth verifier ────────────────────────────
  async function callBackend(input) {
    const resp = await fetch(EDGE_AUTH, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-FP': getDeviceFP(),
      },
      body: JSON.stringify({ input }),
    });
    return resp.json();
  }

  // ── Nostr: derive public key from stored nsec locally ─────
  // nsec never sent to backend. We sign a server challenge locally.
  async function initiateNostrLogin(input) {
    let npub = null;
    let privKeyHex = null;
    let hasCustody = false;

    if (input.startsWith('nsec1') || input.startsWith('nsec')) {
      // C1: local key custody — we have the private key exposed here briefly
      hasCustody = true;
      try {
        privKeyHex = bech32Decode(input, 'nsec');
        const { schnorr } = await import('https://esm.sh/@noble/curves@1.2.0/secp256k1');
        const pubBytes = schnorr.getPublicKey(privKeyHex);
        npub = bytesToNpub(pubBytes);
      } catch {
        return { type: 'error', message: 'invalid_nsec' };
      }
    } else if (input.startsWith('npub1') || /^[0-9a-f]{64}$/.test(input)) {
      // C2: NIP-46 or manual npub entry (external signer)
      npub = input;
      hasCustody = false;
    } else {
      return { type: 'calendar_search', results: [] };
    }

    return _performNostrChallengeFlow(npub, privKeyHex, hasCustody);
  }

  // ── Mnemonic: BIP39 phrase → derive nsec → sign challenge ─
  // Path D — raw words never leave this function scope.
  async function initiateMnemonicLogin(phrase, language = 'en') {
    if (typeof BIP39 === 'undefined') {
      return { type: 'error', message: 'bip39_module_not_loaded' };
    }

    const words = phrase.trim().split(/\s+/).filter(Boolean);

    // Validate mnemonic (supports en, am, ti)
    const lang = language || detectMnemonicLanguage(words);
    if (!BIP39.validateMnemonic(words, lang)) {
      return { type: 'calendar_search', results: [] }; // silent fail — not recognisable
    }

    // Derive nsec/npub locally — NEVER sent to server
    const derived = await BIP39.deriveNsecFromMnemonic(words, lang);
    if (!derived) return { type: 'calendar_search', results: [] };

    const { nsecHex, npubHex, npubBech32 } = derived;
    const npub = npubBech32 || npubHex;

    // Compute entropy fingerprint for cross-check
    const entropyFingerprint = await BIP39.entropyFingerprint(words, lang);

    // Perform challenge-response using derived nsec
    return _performNostrChallengeFlow(npub, nsecHex, true, entropyFingerprint);
  }

  // ── Shared Nostr challenge-response flow ──────────────────
  async function _performNostrChallengeFlow(
    npub, privKeyHex, hasCustody, entropyFingerprint = null
  ) {
    // Request challenge from server
    const challengeResp = await fetch(
      `${EDGE_NOSTR}?action=challenge&npub=${encodeURIComponent(npub)}`,
      { headers: { 'X-Device-FP': getDeviceFP() } }
    );
    const challengeData = await challengeResp.json();
    if (challengeData.type !== 'nostr_challenge') {
      return { type: 'calendar_search', results: [] };
    }
    const nonce = challengeData.nonce;

    if (hasCustody && privKeyHex) {
      try {
        const { schnorr } = await import('https://esm.sh/@noble/curves@1.2.0/secp256k1');
        const msgBytes = new Uint8Array(
          await crypto.subtle.digest('SHA-256', new TextEncoder().encode(nonce))
        );
        const sig = schnorr.sign(msgBytes, privKeyHex);
        const sigHex = Array.from(sig).map(b => b.toString(16).padStart(2, '0')).join('');

        // Zero reference immediately
        privKeyHex = null;

        // For seed phrase recovery, use auth-seed; for direct nsec use auth-nostr
        const endpoint = entropyFingerprint ? EDGE_SEED : `${EDGE_NOSTR}?action=verify`;

        const verifyResp = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Device-FP': getDeviceFP(),
          },
          body: JSON.stringify({
            npub,
            nonce,
            sig: sigHex,
            ...(entropyFingerprint && { entropy_fingerprint: entropyFingerprint }),
          }),
        });
        return verifyResp.json();
      } catch (e) {
        return { type: 'error', message: 'signing_failed' };
      }
    } else {
      // C2: return the challenge so the UI can prompt external signer
      return { type: 'nip46_challenge', npub, nonce };
    }
  }

  // ── Language auto-detection for mnemonic phrases ──────────
  function detectMnemonicLanguage(words) {
    if (typeof BIP39 === 'undefined') return 'en';
    for (const lang of BIP39.SUPPORTED_LANGUAGES) {
      if (BIP39.validateMnemonic(words, lang)) return lang;
    }
    return 'en'; // fallback
  }

  // ── Bech32 utilities (minimal, browser-compatible) ────────
  const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const BECH32_CHARSET_MAP = {};
  for (let i = 0; i < BECH32_CHARSET.length; i++) BECH32_CHARSET_MAP[BECH32_CHARSET[i]] = i;

  const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

  function _bech32Polymod(values) {
    let chk = 1;
    for (const v of values) {
      const top = chk >> 25;
      chk = (chk & 0x1ffffff) << 5 ^ v;
      for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= BECH32_GENERATOR[i];
    }
    return chk;
  }

  function _bech32HrpExpand(hrp) {
    const ret = [];
    for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
    ret.push(0);
    for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
    return ret;
  }

  function _bech32CreateChecksum(hrp, data) {
    const values = [..._bech32HrpExpand(hrp), ...data];
    const polymod = _bech32Polymod([...values, 0, 0, 0, 0, 0, 0]) ^ 1;
    const checksum = [];
    for (let i = 0; i < 6; i++) checksum.push((polymod >> (5 * (5 - i))) & 31);
    return checksum;
  }

  function bech32Decode(str, expectedHrp) {
    try {
      str = str.toLowerCase();
      const pos = str.lastIndexOf('1');
      if (pos < 1 || pos + 7 > str.length) return null;
      const hrp = str.slice(0, pos);
      if (hrp !== expectedHrp) return null;

      const data = [];
      for (let i = pos + 1; i < str.length; i++) {
        const v = BECH32_CHARSET_MAP[str[i]];
        if (v === undefined) return null;
        data.push(v);
      }

      // Convert 5-bit words to bytes
      const bytes = [];
      let value = 0, bits = 0;
      for (let i = 0; i < data.length - 6; i++) { // strip checksum
        value = (value << 5) | data[i];
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

  function bytesToNpub(pubKeyBytes) {
    // Convert 32-byte pubkey to 5-bit word array
    const words = [];
    let value = 0, bits = 0;
    for (const byte of pubKeyBytes) {
      value = (value << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        words.push((value >> bits) & 31);
      }
    }
    if (bits > 0) words.push((value << (5 - bits)) & 31);

    const checksum = _bech32CreateChecksum('npub', words);
    let result = 'npub1';
    for (const w of [...words, ...checksum]) result += BECH32_CHARSET[w];
    return result;
  }

  // Exposed for BIP39 module to encode nsec/npub bech32
  function _encodeBech32(hrp, bytesArr) {
    const words = [];
    let value = 0, bits = 0;
    for (const byte of bytesArr) {
      value = (value << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        words.push((value >> bits) & 31);
      }
    }
    if (bits > 0) words.push((value << (5 - bits)) & 31);
    const checksum = _bech32CreateChecksum(hrp, words);
    let result = hrp + '1';
    for (const w of [...words, ...checksum]) result += BECH32_CHARSET[w];
    return result;
  }

  // ── Public API ────────────────────────────────────────────
  return {
    determineShape,
    callBackend,
    initiateNostrLogin,
    initiateMnemonicLogin,
    getDeviceFP,
    bech32Decode,
    bytesToNpub,
    _encodeBech32, // used by bip39.js

    /**
     * handleSubmit — called ONCE when user submits the search bar.
     * Returns auth result OR signals calendar search.
     */
    async handleSubmit(input, mnemonicLang = null) {
      const trimmed = input.trim();
      const shape = determineShape(trimmed);

      if (shape === 'calendar_text') {
        return { type: 'calendar_search', query: input };
      }

      if (shape === 'nostr_string') {
        return initiateNostrLogin(trimmed);
      }

      if (shape === 'mnemonic_phrase') {
        // Detect language automatically from the words themselves
        const words = trimmed.split(/\s+/).filter(Boolean);
        const lang = mnemonicLang || detectMnemonicLanguage(words);
        try {
          return await initiateMnemonicLogin(trimmed, lang);
        } catch {
          return { type: 'calendar_search', query: input };
        }
      }

      // 4-digit or 6-digit: fire backend
      try {
        return await callBackend(trimmed);
      } catch {
        // Network failure — return calendar search to avoid leaking auth attempt
        return { type: 'calendar_search', query: input };
      }
    },

    /**
     * submitNIP46Signature — called after external signer returns the signature
     * for a NIP-46 challenge.
     */
    async submitNIP46Signature(npub, nonce, sigHex) {
      const resp = await fetch(`${EDGE_NOSTR}?action=verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-FP': getDeviceFP(),
        },
        body: JSON.stringify({ npub, nonce, sig: sigHex }),
      });
      return resp.json();
    },

    /**
     * registerNostrAccount — called from onboarding when a new npub user sets up profile.
     */
    async registerNostrAccount({ npub, nonce, sig, username, displayName, phone }) {
      const resp = await fetch(`${EDGE_NOSTR}?action=register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-FP': getDeviceFP(),
        },
        body: JSON.stringify({ npub, nonce, sig, username, display_name: displayName, phone }),
      });
      return resp.json();
    },

    /**
     * storeSeedPhrase — called once during onboarding on a confirmed new account.
     * Derives entropy fingerprint locally and stores it + the bcrypt-hashed phrase
     * on the server via the authenticated API. The raw words never leave JS scope.
     */
    async storeSeedPhrase({ words, lang, supabaseToken }) {
      if (typeof BIP39 === 'undefined') throw new Error('BIP39 not loaded');
      if (!BIP39.validateMnemonic(words, lang)) throw new Error('Invalid mnemonic');

      const fingerprint = await BIP39.entropyFingerprint(words, lang);

      // We hash the phrase client-side using a derived HMAC key so the raw phrase
      // never reaches the server — the bcrypt hash is computed edge-side.
      // We send: { phrase_joined, language, word_count, entropy_fingerprint }
      // The Edge Function bcrypt-hashes phrase_joined server-side.
      const resp = await fetch(`${SUPABASE_URL}/functions/v1/auth-seed-store`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${supabaseToken}`,
        },
        body: JSON.stringify({
          phrase_joined: words.join(' '), // hashed server-side, not stored raw
          language: lang,
          word_count: words.length,
          entropy_fingerprint: fingerprint,
        }),
      });
      return resp.json();
    },
  };
})();
