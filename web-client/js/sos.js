/**
 * SafeTrack — SOS Module
 * STRICT MODE: Multi-Relay Broadcast & NIP-44 Encryption
 */

let _sosLat = null, _sosMng = null;

// GAP 1: Relay Pools
const PRIMARY_RELAY_POOL = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band',
  'wss://nostr.wine',
  'wss://relay.snort.social'
];

const FALLBACK_RELAY_POOL = [
  'wss://relay.primal.net',
  'wss://purplepag.es',
  'wss://relay.current.fyi',
  'wss://nostr.oxtr.dev'
];

// Extracted globally for native gesture injection (e.g. Volume Down 3x bridged from Capacitor)
window.triggerNativeSOS = function() {
  triggerSOS(); 
  setTimeout(() => fireSOS(), 500); // Auto-fire natively bypassing UI confirmation
};

/**
 * Step 1: User taps SOS → show confirmation modal with current location.
 * The device shows NO visible feedback (per Silent Alert spec).
 */
function triggerSOS() {
  document.getElementById('sos-location-preview').textContent = 'Getting your location…';
  openModal('modal-sos-confirm');

  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        _sosLat = pos.coords.latitude;
        _sosMng = pos.coords.longitude;
        document.getElementById('sos-location-preview').textContent =
          `📍 ${_sosLat.toFixed(5)}, ${_sosMng.toFixed(5)} (±${Math.round(pos.coords.accuracy)}m)`;
      },
      () => {
        document.getElementById('sos-location-preview').textContent = 'Location unavailable — SOS will be sent without exact coordinates';
      },
      { timeout: 8000, enableHighAccuracy: true }
    );
  } else {
    document.getElementById('sos-location-preview').textContent = 'Geolocation not supported on this device';
  }
}

/**
 * Utility: Simulates fetching memory-cached private key during active session
 */
async function _getMemoryPrivateKey() {
  const stUser = localStorage.getItem('st_user');
  if (!stUser) return null;
  // STRICT MODE: SOS-specific keypair check
  return AppState.sosPrivKeyHex || AppState.privKeyHex || null; 
}

/**
 * Step 2: User confirms → fire the SOS alert.
 * ZERO-EXPOSURE: Builds Nostr Event natively and signs it *before* it leaves the client.
 */
async function fireSOS() {
  const btn = document.getElementById('btn-sos-fire');
  btn.disabled = true;
  btn.textContent = 'Sending…';

  try {
    const settings = AppState.settings || {};
    const privKeyHex = await _getMemoryPrivateKey();
    if (!privKeyHex) throw new Error('No secure key found in memory. Please re-login.');

    const { getEventHash, getSignature, getPublicKey, nip44 } = await import('https://esm.sh/nostr-tools@1.17.0');
    const pubKey = getPublicKey(privKeyHex);

    // GAP 2: NIP-44 Encryption (ENCRYPTED PAYLOAD)
    const rawPayload = JSON.stringify({
      lat: _sosLat || 0,
      lng: _sosMng || 0,
      mode: settings.sosMode || 'SILENT_ALERT',
      groupId: settings.sosGroupId || null,
      is_drill: settings.drillModeEnabled || false,
      timestamp: Date.now()
    });

    const recipients = (settings.emergencyContacts || []).map(c => c.pubkey);
    if (settings.groupPubkey) recipients.push(settings.groupPubkey);

    let firstEvent = null;

    // Create and sign events per recipient
    for (const targetPub of recipients) {
      try {
        const ciphertext = nip44.encrypt(privKeyHex, targetPub, rawPayload);
        const event = {
          kind: 10001,
          pubkey: pubKey,
          created_at: Math.floor(Date.now() / 1000),
          tags: [
            ['t', 'sos'],
            ['p', targetPub],
            ...(settings.drillModeEnabled ? [['drill', 'true']] : [])
          ],
          content: ciphertext
        };
        event.id = getEventHash(event);
        event.sig = getSignature(event, privKeyHex);

        if (!firstEvent) firstEvent = event;
        broadcastPromises.push(directRelayBroadcast(event));
      } catch (e) {
        console.error(`Encryption failed for recipient ${targetPub}:`, e);
      }
    }

    // Parallel: Backend passive receiver
    broadcastPromises.push(API.post('/sos/trigger', {
      lat: _sosLat,
      lng: _sosMng,
      is_drill: settings.drillModeEnabled
    }).catch(e => console.error('Backend broadcast failed:', e)));

    const results = await Promise.all(broadcastPromises);
    const relaySuccesses = results.filter(r => r === true).length;

    closeModal('modal-sos-confirm');

    if (relaySuccesses < 2 && !navigator.onLine) {
      // GAP 4: Offline SMS Fallback Offer
      const smsPayloads = compressEventForSMS(firstEvent); 
      const payloadsJson = encodeURIComponent(JSON.stringify(smsPayloads));
      showToast(`📵 Offline. <button onclick="triggerSMSFallback('${payloadsJson}')" style="color:var(--clr-accent);text-decoration:underline">Send via SMS instead?</button>`, 'warn', 15000);
    } else {
      showToast(`🚨 Alert broadcast to ${relaySuccesses} relays`, 'info', 5000);
    }

    goToPanel('alerts', document.getElementById('nav-alerts'));
    loadAlerts();
  } catch (err) {
    showToast(`SOS failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send Alert';
  }
}

/**
 * GAP 4: Nostr-to-SMS Compression & Fragmentation
 * Format Single: ST1:<base64>
 * Format Multi: ST1/[part]/[total]:<base64_fragment>
 */
function compressEventForSMS(event) {
  if (!event) return [];
  try {
    // STRICT MODE: We need full ID and Sig for Gateway validation
    const fullPayload = {
      i: event.id,
      p: event.pubkey,
      s: event.sig,
      c: event.content, 
      a: event.created_at
    };
    const b64 = btoa(JSON.stringify(fullPayload));
    
    const MAX_CHUNK = 130; // Leave room for prefix and metadata
    if (b64.length <= MAX_CHUNK) {
      return [`ST1:${b64}`];
    }

    // Fragmentation logic
    const chunks = [];
    const total = Math.ceil(b64.length / MAX_CHUNK);
    for (let i = 0; i < total; i++) {
      const part = b64.slice(i * MAX_CHUNK, (i + 1) * MAX_CHUNK);
      chunks.push(`ST1/${i + 1}/${total}:${part}`);
    }
    return chunks;
  } catch (e) {
    return [];
  }
}

window.triggerSMSFallback = function(payloadsJson) {
  const payloads = JSON.parse(decodeURIComponent(payloadsJson));
  const gatewayNumber = AppState.settings.smsGatewayNumber || '+15074311828'; 
  
  // Send each fragment. Note: Most mobile browsers only allow one window.open at a time.
  // In a real mobile app (Capacitor/Cordova), we would use a native SMS plugin to send in background.
  // For web-client, we send the first one and warn the user.
  if (payloads.length > 1) {
    showToast(`⚠️ Multi-part alert. Please send all ${payloads.length} texts that follow.`, 'warn');
  }

  payloads.forEach((p, idx) => {
    setTimeout(() => {
      const intent = `sms:${gatewayNumber}?body=${encodeURIComponent(p)}`;
      window.open(intent, '_blank');
    }, idx * 1500); // Stagger opens to bypass popup blockers
  });
};

/**
 * GAP 1 & 3: Direct WebSocket Broadcast with Triage
 */
async function directRelayBroadcast(event) {
  // Extract recipient npub from the event tags
  const pTag = event.tags.find(t => t[0] === 'p');
  const targetPubkey = pTag ? pTag[1] : null;
  
  // GAP 3 & 4: Triage order
  const healthyRelays = window.NostrP2P ? NostrP2P.getBestRelays(3) : [];
  const contactRelays = (AppState.contactRelays && targetPubkey) 
    ? (AppState.contactRelays[targetPubkey] || []).map(r => r.url)
    : [];

  const allRelays = [
    ...healthyRelays,         // Tier 1: Health-monitored (Optimal)
    ...contactRelays,         // Tier 2: Contact-specific (NIP-65)
    ...PRIMARY_RELAY_POOL,    // Tier 3: Hardcoded Primary
    ...FALLBACK_RELAY_POOL    // Tier 4: Hardcoded Fallback
  ];

  // Unique relays only
  const relayPool = [...new Set(allRelays)];
  let successCount = 0;

  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(false), 8000); 
    
    relayPool.forEach(url => {
      try {
        const ws = new WebSocket(url);
        ws.onopen = () => ws.send(JSON.stringify(['EVENT', event]));
        ws.onmessage = (msg) => {
          try {
            const [type, id, ok] = JSON.parse(msg.data);
            if (type === 'OK' && id === event.id && ok) {
              successCount++;
              if (successCount >= 2) {
                clearTimeout(timeout);
                resolve(true);
              }
            }
          } catch(e) {}
          ws.close();
        };
        ws.onerror = () => ws.close();
      } catch(e) {
        console.error(`WebSocket setup failed for ${url}:`, e);
      }
    });
  });
}

/**
 * Helper to cache offline SOS triggers for Service Worker Sync
 */
async function cacheEventForBackgroundSync(eventData) {
  return new Promise((resolve, reject) => {
    const request = window.indexedDB.open('SafeTrackDB', 1);
    request.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('offline_sos')) {
        db.createObjectStore('offline_sos', { keyPath: 'id', autoIncrement: true });
      }
    };
    request.onsuccess = (e) => {
      const db = e.target.result;
      const tx = db.transaction('offline_sos', 'readwrite');
      tx.objectStore('offline_sos').add({ data: eventData, timestamp: Date.now() });
      tx.oncomplete = () => {
        navigator.serviceWorker.ready.then(reg => {
          if (reg.sync) reg.sync.register('sync-sos');
        });
        resolve();
      };
      tx.onerror = reject;
    };
    request.onerror = reject;
  });
}

/**
 * Load SOS alerts (outbound events & inbox).
 */
async function loadAlerts() {
  loadOutboundAlerts();
  loadInboxAlerts();
}

async function loadOutboundAlerts() {
  try {
    const events = await API.get('/sos/events');
    const list = document.getElementById('alerts-outbound');
    if (!events.length) {
      list.innerHTML = '<div class="empty-state">No SOS events triggered yet</div>';
      return;
    }
    list.innerHTML = events.map(ev => renderSosEvent(ev)).join('');
  } catch (err) {
    console.error('Load SOS events error:', err);
  }
}

function renderSosEvent(ev) {
  const isResolved = !!ev.resolvedAt;
  const isDrill = ev.is_drill;
  const timeStr = new Date(ev.createdAt).toLocaleString();
  const acks = ev.notifications || [];
  return `
    <div class="sos-event-card">
      <div class="sos-event-header">
        <div class="sos-event-indicator ${isResolved ? 'resolved' : ''}" style="${isDrill ? 'background: var(--clr-amber); box-shadow: 0 0 10px var(--clr-amber)' : ''}"></div>
        <div class="sos-event-info">
          <div class="sos-event-title">${isDrill ? '🛡️ DRILL' : '🚨 SOS'} — ${ev.mode.replace(/_/g,' ')}</div>
          <div class="sos-event-time">${timeStr}</div>
        </div>
        ${!isResolved ? `<button class="sos-resolve-btn" onclick="resolveSOS('${ev.id}')" aria-label="Mark SOS as resolved">Resolve</button>` : '<span style="font-size:12px;color:var(--clr-success)">✓ Resolved</span>'}
      </div>
      ${acks.length ? `
        <div class="sos-ack-list">
          ${acks.map(a => `
            <div class="sos-ack-item">
              <span class="sos-ack-name">${escHtml(a.notifiedId.slice(0,8))}…</span>
              <span class="sos-ack-status ${getAckClass(a.status)}">${formatAckStatus(a.status)}</span>
            </div>
          `).join('')}
        </div>
      ` : ''}
    </div>
  `;
}

async function resolveSOS(eventId) {
  try {
    await API.put(`/sos/${eventId}/resolve`, {});
    showToast('SOS event resolved', 'success');
    loadOutboundAlerts();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  }
}

async function loadInboxAlerts() {
  try {
    const items = await API.get('/sos/inbox');
    const list = document.getElementById('alerts-inbox');

    // Update badge
    const unacked = items.filter(i => i.status === 'SENT' || i.status === 'DELIVERED');
    const badge = document.getElementById('alert-badge');
    if (badge) {
       badge.textContent = unacked.length;
       badge.classList.toggle('hidden', unacked.length === 0);
    }
    
    // Specifically update the new internal Bell SVG badge
    if (window.IconResolver) {
       IconResolver.updateAlertBadge(unacked.length);
    }

    if (!items.length) {
      list.innerHTML = '<div class="empty-state">No SOS alerts received</div>';
      return;
    }
    list.innerHTML = items.map(n => renderInboxItem(n)).join('');
  } catch (err) {
    console.error('Load inbox error:', err);
  }
}

function renderInboxItem(n) {
  const ev = n.sosEvent;
  const from = ev.triggeredBy;
  const name = from.displayName || from.username;
  const timeStr = new Date(n.createdAt).toLocaleString();
  const status = n.status;
  const isDrill = ev.is_drill;
  const canAck = status === 'SENT' || status === 'DELIVERED';

  return `
    <div class="sos-inbox-item" style="${isDrill ? 'border-left: 4px solid var(--clr-amber)' : 'border-left: 4px solid var(--clr-red)'}">
      <div class="sos-inbox-icon">${isDrill ? '🛡️' : '🚨'}</div>
      <div class="sos-inbox-info">
        <div class="sos-inbox-from">${escHtml(name)} sent a ${isDrill ? 'DRILL' : 'SOS'}</div>
        <div class="sos-inbox-time">${timeStr} <span style="opacity:0.5">· Hops: ${ev.hops || 1}</span></div>
      </div>
      ${canAck ? `
        <div class="sos-inbox-actions triage-pill-actions">
          <button class="btn-ack-seen" onclick="ackSOSEndpoint('${ev.id}','I will Help',this)" aria-label="Respond as Endpoint">🏃 I'll Help</button>
          <button class="btn-ack-way" onclick="relaySOSNode('${ev.id}', ${ev.hops || 1}, this)" aria-label="Relay to Network as Node">📡 Relay</button>
        </div>
      ` : `<span style="font-size:12px;color:var(--clr-success);font-weight:600">${formatAckStatus(status)}</span>`}
    </div>
  `;
}

/** Triage Core Mechanic: Response (ENDPOINT) */
async function ackSOSEndpoint(eventId, message, btn) {
  btn.disabled = true;
  try {
    await API.put(`/sos/${eventId}/ack`, { ackMessage: message, role: 'endpoint' });
    showToast(`SOS acknowledged — Heading there.`, 'success');
    await loadInboxAlerts();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
    btn.disabled = false;
  }
}

/** Triage Core Mechanic: Relay (NODE) */
async function relaySOSNode(originalEventId, currentHops, btn) {
  btn.disabled = true;
  try {
    const privKeyHex = await _getMemoryPrivateKey();
    let signedRelayEvent = null;

    // Build the NIP-01 Relay Broadcast Signed Event
    if (privKeyHex) {
      const { getEventHash, getSignature, getPublicKey } = await import('https://esm.sh/nostr-tools@1.17.0');
      signedRelayEvent = {
        kind: 10001,
        pubkey: getPublicKey(privKeyHex),
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['e', originalEventId],
          ['hops', (currentHops + 1).toString()]
        ],
        content: `Relaying SOS for ${originalEventId}`
      };
      signedRelayEvent.id = getEventHash(signedRelayEvent);
      signedRelayEvent.sig = getSignature(signedRelayEvent, privKeyHex);
    }
    
    await API.post(`/sos/relay`, signedRelayEvent || { originalEventId, hops: parseFloat(currentHops) + 1 });
    showToast(`Radar pinged. Relayed to your trusted network.`, 'success');
    await loadInboxAlerts();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
    btn.disabled = false;
  }
}

function getAckClass(status) {
  if (status === 'ON_MY_WAY') return 'ack-on-way';
  if (status === 'SEEN') return 'ack-seen';
  return 'ack-sent';
}

function formatAckStatus(status) {
  return status === 'ON_MY_WAY' ? '🏃 On my way' : status === 'SEEN' ? '👁 Seen' : '⏳ Sent';
}
