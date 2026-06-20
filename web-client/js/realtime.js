/**
 * SafeTrack Web Client — Supabase Realtime Manager
 * Replaces Socket.IO entirely.
 *
 * Channel layout (mirrors the server-side broadcast() calls):
 *   "user:<userId>"   — private events: sos:alert, sos:ack, ping:forced,
 *                        contact:request, contact:accepted, contact:revoked
 *   "loc:<userId>"    — location events: location:update (one per watched contact)
 *
 * Usage:
 *   RealtimeManager.connect(userId, accessToken)  — call after auth success
 *   RealtimeManager.watchContact(contactId)       — subscribe to a contact's location
 *   RealtimeManager.unwatchContact(contactId)     — unsubscribe
 *   RealtimeManager.disconnect()                  — called on logout
 *
 * All events are dispatched as native CustomEvents on `window` so that
 * any part of the app can listen without tight coupling:
 *   window.addEventListener('st:location:update', e => console.log(e.detail))
 *   window.addEventListener('st:sos:alert',       e => console.log(e.detail))
 *   window.addEventListener('st:sos:ack',         e => console.log(e.detail))
 *   window.addEventListener('st:ping:forced',     e => console.log(e.detail))
 *   window.addEventListener('st:contact:request', e => console.log(e.detail))
 */

const RealtimeManager = (() => {
  let _supabase = null;
  let _userChannel = null;
  const _locChannels = new Map(); // contactId → channel

  // ─── Helpers ──────────────────────────────────────────────────────────────
  function dispatch(eventName, detail) {
    window.dispatchEvent(new CustomEvent(`st:${eventName}`, { detail }));
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  /**
   * Call immediately after a user successfully authenticates.
   * @param {string} userId      — The authenticated user's ID
   * @param {string} accessToken — The JWT access token for Supabase auth
   */
  function connect(userId, accessToken) {
    if (!window.SUPABASE_URL || !window.SUPABASE_ANON_KEY) {
      console.warn('[Realtime] SUPABASE_URL or SUPABASE_ANON_KEY not set. Realtime disabled.');
      return;
    }

    // Initialize Supabase client with user's token
    _supabase = window.supabase.createClient(
      window.SUPABASE_URL,
      window.SUPABASE_ANON_KEY,
      {
        global: {
          headers: { Authorization: `Bearer ${accessToken}` },
        },
        realtime: {
          params: { eventsPerSecond: 10 },
        },
      }
    );

    // ── Private user channel ─────────────────────────────────────────────
    _userChannel = _supabase
      .channel(`user:${userId}`, { config: { private: true } })
      .on('broadcast', { event: 'sos:alert' }, ({ payload }) => {
        console.log('[Realtime] SOS alert received:', payload);
        dispatch('sos:alert', payload);
        showSOSNotification(payload);
      })
      .on('broadcast', { event: 'sos:ack' }, ({ payload }) => {
        console.log('[Realtime] SOS ack received:', payload);
        dispatch('sos:ack', payload);
      })
      .on('broadcast', { event: 'ping:forced' }, ({ payload }) => {
        console.log('[Realtime] Forced ping received:', payload);
        dispatch('ping:forced', payload);
        handleForcedPing(payload);
      })
      .on('broadcast', { event: 'contact:request' }, ({ payload }) => {
        dispatch('contact:request', payload);
      })
      .on('broadcast', { event: 'contact:accepted' }, ({ payload }) => {
        dispatch('contact:accepted', payload);
      })
      .on('broadcast', { event: 'contact:revoked' }, ({ payload }) => {
        dispatch('contact:revoked', payload);
      })
      .subscribe((status) => {
        console.log(`[Realtime] user:${userId} channel status: ${status}`);
      });

    console.log(`[Realtime] Connected as user:${userId}`);
  }

  /**
   * Subscribe to a contact's live location stream.
   * Call once per contact after their link is accepted.
   * @param {string} contactId — The contact's user ID
   */
  function watchContact(contactId) {
    if (_locChannels.has(contactId)) return; // already subscribed
    if (!_supabase) { console.warn('[Realtime] Not connected. Call connect() first.'); return; }

    const ch = _supabase
      .channel(`loc:${contactId}`)
      .on('broadcast', { event: 'location:update' }, ({ payload }) => {
        dispatch('location:update', payload);
        updateMapMarker(payload);
      })
      .subscribe();

    _locChannels.set(contactId, ch);
    console.log(`[Realtime] Watching location of contact: ${contactId}`);
  }

  /**
   * Unsubscribe from a contact's location channel (e.g., link revoked).
   * @param {string} contactId
   */
  function unwatchContact(contactId) {
    const ch = _locChannels.get(contactId);
    if (ch) {
      _supabase.removeChannel(ch);
      _locChannels.delete(contactId);
      console.log(`[Realtime] Stopped watching contact: ${contactId}`);
    }
  }

  /**
   * Disconnect all channels. Call on logout.
   */
  function disconnect() {
    if (!_supabase) return;
    if (_userChannel) _supabase.removeChannel(_userChannel);
    _locChannels.forEach(ch => _supabase.removeChannel(ch));
    _locChannels.clear();
    _userChannel = null;
    _supabase = null;
    console.log('[Realtime] Disconnected.');
  }

  // ─── Internal Handlers ────────────────────────────────────────────────────

  /** Show a browser notification or in-app SOS banner. */
  function showSOSNotification(payload) {
    // In-app banner (the existing SOS notification DOM element)
    const banner = document.getElementById('sos-notification-banner');
    if (banner) {
      document.getElementById('sos-banner-name').textContent = payload.triggeredById || 'A contact';
      document.getElementById('sos-banner-mode').textContent = payload.mode || 'SILENT_ALERT';
      banner.classList.add('visible');
      setTimeout(() => banner.classList.remove('visible'), 10000);
    }

    // Browser push notification (if permission granted)
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification('⚠️ SafeTrack SOS Alert', {
        body: `Emergency from contact ${payload.triggeredById}. Mode: ${payload.mode}`,
        icon: '/calendar-icon.svg',
        requireInteraction: true,
      });
    }
  }

  /** Respond to a forced ping by posting the current GPS location. */
  async function handleForcedPing(payload) {
    if (!navigator.geolocation) return;

    navigator.geolocation.getCurrentPosition(async (pos) => {
      try {
        const token = localStorage.getItem('st_access_token');
        await fetch(`${window.API_BASE_URL}/location/update`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify({
            lat: pos.coords.latitude,
            lng: pos.coords.longitude,
            accuracy: pos.coords.accuracy,
            source: 'REMOTE_PING_FORCED',
          }),
        });
        console.log('[Realtime] Responded to forced ping:', payload.pingId);
      } catch (err) {
        console.error('[Realtime] Failed to respond to ping:', err);
      }
    }, null, { enableHighAccuracy: true, timeout: 8000 });
  }

  /** Update the Leaflet map marker for a contact (if map is active). */
  function updateMapMarker(payload) {
    // The main map module listens for 'st:location:update' CustomEvent
    // This is a no-op here — handled by the map module separately.
    // Kept as a hook for debugging.
    if (window._debugRealtime) {
      console.log('[Realtime] Location update:', payload);
    }
  }

  return { connect, watchContact, unwatchContact, disconnect };
})();

// ─── Auto-restore session on page reload ──────────────────────────────────
(function restoreRealtimeSession() {
  const token  = localStorage.getItem('st_access_token');
  const userId = localStorage.getItem('st_user_id');
  if (token && userId) {
    // Wait for DOM + supabase SDK to be ready
    window.addEventListener('DOMContentLoaded', () => {
      RealtimeManager.connect(userId, token);
    });
  }
})();

// Expose globally so auth-router.js and other modules can call it
window.RealtimeManager = RealtimeManager;
