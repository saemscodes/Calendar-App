/**
 * SafeTrack — Supabase Admin Client
 *
 * Uses the SERVICE_ROLE_KEY which bypasses Row Level Security.
 * This client is ONLY used server-side (inside Express routes) for:
 *   1. Broadcasting real-time events to connected clients via Supabase Realtime
 *   2. Any admin-level DB operations (e.g. creating users during auth flows)
 *
 * NEVER expose the SERVICE_ROLE_KEY to the browser or mobile apps.
 */
const { createClient } = require('@supabase/supabase-js');

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.warn('[Supabase] Warning: SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set. Realtime broadcast will be unavailable.');
}

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL  || '',
  process.env.SUPABASE_SERVICE_ROLE_KEY || '',
  {
    auth: {
      autoRefreshToken: false,
      persistSession:   false,
    },
  }
);

/**
 * Broadcast a real-time event to a named Supabase Realtime channel.
 * This is the Server → Client push path, replacing Socket.IO.
 *
 * Channel naming convention (mirrors the old Socket.IO rooms):
 *   "user:<userId>"   — private: SOS alerts, ping notifications, contact requests
 *   "loc:<userId>"    — location: live coordinates broadcast to watchers
 *
 * On the client side, users subscribe to their own "user:<id>" channel
 * and subscribe to "loc:<contactId>" for each contact they are watching.
 *
 * @param {string} channel  - Channel name, e.g. "user:abc-123"
 * @param {string} event    - Event name, e.g. "sos:alert"
 * @param {object} payload  - JSON-serialisable data to send
 */
async function broadcast(channel, event, payload) {
  try {
    await supabaseAdmin.channel(channel).send({
      type:    'broadcast',
      event,
      payload,
    });
  } catch (err) {
    // Non-fatal: log and continue. The REST response still completes.
    console.error(`[Realtime] Broadcast failed on channel "${channel}" event "${event}":`, err?.message);
  }
}

module.exports = { supabaseAdmin, broadcast };
