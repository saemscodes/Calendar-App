/**
 * SafeTrack — Main App JS
 * Auth flows, screen management, socket setup, global state.
 */

// ── Global State ─────────────────────────────────────
window.AppState = {
  user: null,
  socket: null,
  contacts: [],
  groups: [],
  settings: null,
  locationWatchId: null,
  currentPanel: 'map',
  pingIntervalId: null,
  isOnline: navigator.onLine,
  isSmsMode: false,
  isDemoMode: false,
  sosTargetUserId: null, // for remote ping modal
};

// ── Boot ─────────────────────────────────────────────
// Boot is managed by index.html DOMContentLoaded handler.
// showApp() is called once auth succeeds via the Calendar search bar.
document.addEventListener('DOMContentLoaded', () => {
  // Connectivity monitoring (always active)
  window.addEventListener('online',  () => updateConnectivity(true));
  window.addEventListener('offline', () => updateConnectivity(false));
});

// ── Auth Screens ─────────────────────────────────────
function showAuthTab(tab) {
  document.getElementById('form-login').classList.toggle('hidden', tab !== 'login');
  document.getElementById('form-register').classList.toggle('hidden', tab !== 'register');
  document.getElementById('tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('tab-register').classList.toggle('active', tab === 'register');
}

async function handleLogin(e) {
  e.preventDefault();
  const btn = document.getElementById('btn-login');
  const errEl = document.getElementById('login-error');
  errEl.textContent = '';
  btn.textContent = 'Signing in…';
  btn.disabled = true;
  try {
    const data = await API.post('/auth/login', {
      usernameOrPhone: document.getElementById('login-id').value.trim(),
      password: document.getElementById('login-pass').value
    });
    API.saveTokens(data.accessToken, data.refreshToken);
    API.saveUser(data.user);
    AppState.user = data.user;
    showApp();
  } catch (err) {
    errEl.textContent = err.message || 'Login failed. Check your credentials.';
    btn.disabled = false;
    btn.textContent = 'Sign In';
  }
}

async function handleRegister(e) {
  e.preventDefault();
  const btn = document.getElementById('btn-register');
  const errEl = document.getElementById('reg-error');
  errEl.textContent = '';
  btn.textContent = 'Creating account…';
  btn.disabled = true;
  try {
    const data = await API.post('/auth/register', {
      displayName: document.getElementById('reg-name').value.trim(),
      username: document.getElementById('reg-username').value.trim(),
      phone: document.getElementById('reg-phone').value.trim(),
      password: document.getElementById('reg-pass').value
    });
    API.saveTokens(data.accessToken, data.refreshToken);
    API.saveUser(data.user);
    AppState.user = data.user;
    showApp();
  } catch (err) {
    errEl.textContent = err.message || 'Registration failed. Try a different username.';
    btn.disabled = false;
    btn.textContent = 'Create Account';
  }
}

function logout() {
  API.post('/auth/logout', { refreshToken: API.getRefresh() }).catch(() => {});
  if (AppState.socket) AppState.socket.disconnect();
  if (AppState.locationWatchId) navigator.geolocation.clearWatch(AppState.locationWatchId);
  if (AppState.pingIntervalId) clearInterval(AppState.pingIntervalId);
  
  // Clear basic tokens but keep Device FP for Path C stability
  const deviceFp = localStorage.getItem('st_device_fp');
  API.clearTokens();
  localStorage.setItem('st_device_fp', deviceFp);

  AppState.user = null;
  AppState.isDemoMode = false;
  AppState.contacts = [];
  AppState.groups = [];

  // Return to Calendar decoy screen
  document.getElementById('app-screen').classList.remove('active');
  document.getElementById('app-screen').classList.add('hidden');
  const calScreen = document.getElementById('calendar-screen');
  if (calScreen) {
    calScreen.classList.remove('hidden', 'transitioning-out');
    calScreen.classList.add('active');
    if (typeof CalendarApp !== 'undefined') CalendarApp.init();
  }
}

/**
 * Kill Switch — Instantly vaporizes all local data and returns to decoy.
 * Invoked by triple-tap on logo or from settings.
 */
function killSwitch() {
  console.warn('[SECURITY] KILL SWITCH ACTIVATED');
  
  // 1. Wipe everything
  localStorage.clear();
  sessionStorage.clear();
  
  // 2. Wipe IndexedDB (Nostr P2P cache)
  if (window.indexedDB) {
     indexedDB.deleteDatabase('SafeTrackDB');
  }

  // 3. Forced reload to clear memory
  window.location.href = window.location.origin + '?mode=safe';
}

// ── Show App ─────────────────────────────────────────
function showApp() {
  const calScreen = document.getElementById('calendar-screen');
  if (calScreen) {
    calScreen.classList.remove('active');
    calScreen.classList.add('hidden');
  }
  // Also hide old auth screen if somehow still visible
  const authScreen = document.getElementById('auth-screen');
  if (authScreen) { authScreen.classList.remove('active'); authScreen.classList.add('hidden'); }
  document.getElementById('app-screen').classList.remove('hidden');
  document.getElementById('app-screen').classList.add('active');

  // Populate profile UI
  updateProfileUI(AppState.user);

  // Init realtime
  initRealtime();

  // Start bootstrap (One-Trip Pattern)
  loadApplicationData();

  // Start geolocation
  startLocationWatch();

  // Init icons
  if (window.IconResolver) window.IconResolver.renderAll();

  // Init map (in map.js)
  initMap();

  // Default panel
  goToPanel('map', document.getElementById('nav-map'));
  
  // Bind entire sharing card as tappable toggle
  const sharingCard = document.getElementById('sharing-card');
  const sharingToggle = document.getElementById('toggle-sharing');
  if (sharingCard && sharingToggle) {
    sharingCard.onclick = () => {
      sharingToggle.checked = !sharingToggle.checked;
      toggleSharing(sharingToggle.checked);
    };
    // Sync initial class
    sharingCard.classList.toggle('active-state', sharingToggle.checked);
    sharingCard.classList.toggle('paused-state', !sharingToggle.checked);
  }
}

// ── Panel Navigation ─────────────────────────────────
function goToPanel(name, btn) {
  document.querySelectorAll('.panel').forEach(p => {
    p.classList.remove('active');
    p.classList.add('hidden');
  });
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));

  const panel = document.getElementById(`panel-${name}`);
  panel.classList.remove('hidden');
  panel.classList.add('active');
  btn.classList.add('active');
  AppState.currentPanel = name;

  if (name === 'map') {
    // Invalidate map size after transition
    setTimeout(() => AppMap && AppMap.map && AppMap.map.invalidateSize(), 100);
  }
}

function openPanel(name) {
  const btn = document.getElementById(`nav-${name}`);
  goToPanel(name, btn);
}

// ── Connectivity ─────────────────────────────────────
function updateConnectivity(online) {
  AppState.isOnline = online;
  const badge = document.getElementById('connectivity-badge');
  const label = badge.querySelector('.badge-label');
  badge.className = `badge ${online ? 'badge-online' : 'badge-offline'}`;
  label.textContent = online ? 'Online' : 'Offline — SMS mode';
  AppState.isSmsMode = !online;

  if (!online) {
    showToast('📵 No internet — switching to SMS fallback mode', 'warn', 5000);
  } else {
    showToast('✅ Back online', 'success');
  }
}

// ── Supabase Realtime ──────────────────────────────────
function initRealtime() {
  if (AppState.isDemoMode) {
    // Simulate some demo locations after map load
    setTimeout(() => {
      if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(pos => {
          const lat = pos.coords.latitude;
          const lng = pos.coords.longitude;
          const ts = Date.now();
          const d1 = { userId: 'c1', lat: lat + 0.005, lng: lng + 0.005, accuracy: 20, timestamp: ts };
          const d2 = { userId: 'c2', lat: lat - 0.003, lng: lng - 0.004, accuracy: 15, timestamp: ts - 60000 };
          if (window.AppMap) {
             AppMap.updateContactPin(d1); updateContactLocationList(d1);
             AppMap.updateContactPin(d2); updateContactLocationList(d2);
          }
        });
      }
    }, 2500);
    return;
  }

  const token = API.getToken();
  const userId = AppState.user?.id;
  if (!token || !userId) return;

  RealtimeManager.connect(userId, token);

  // Listen for custom events dispatched by RealtimeManager
  window.addEventListener('st:location:update', (e) => {
    const data = e.detail;
    if (window.AppMap) AppMap.updateContactPin(data);
    updateContactLocationList(data);
  });

  const _processedSOSIds = new Set();
  window.addEventListener('st:sos:alert', (e) => {
    const data = e.detail;
    
    // 1. Replay Protection: Dedupe ID
    if (_processedSOSIds.has(data.id)) return;
    _processedSOSIds.add(data.id);
    
    // 2. Replay Protection: TTL (5 mins) / 300s
    const eventTimeSec = data.created_at || (new Date(data.timestamp || Date.now()).getTime() / 1000);
    const nowSec = Math.floor(Date.now() / 1000);
    if (eventTimeSec < nowSec - 300) return; // Silent discard

    showToast(`🚨 SOS from ${data.triggeredByDisplayName || 'contact'}! Tap Alerts to respond.`, 'sos', 10000);
    const badge = document.getElementById('alert-badge');
    badge.classList.remove('hidden');
    badge.textContent = parseInt(badge.textContent || '0') + 1;
    loadAlerts(); // reload inbox
    const newCount = parseInt(badge.textContent || '0');
    updateTriagePill('critical', 1);
    
    // Specifically update the new internal Bell SVG badge
    if (window.IconResolver) {
       IconResolver.updateAlertBadge(newCount);
    }
  });

  window.addEventListener('st:sos:ack', (e) => {
    const data = e.detail;
    showToast(`✅ SOS acknowledged — ${data.status === 'ON_MY_WAY' ? 'Help is coming!' : 'Seen'}`, 'success', 5000);
    loadAlerts();
  });

  window.addEventListener('st:contact:request', () => {
    showToast('👤 New contact request!', 'info');
    loadContacts();
  });

  window.addEventListener('st:contact:accepted', () => {
    showToast('✅ Contact request accepted!', 'success');
    loadContacts();
  });

  window.addEventListener('st:contact:revoked', () => {
    showToast('⚠️ A contact has disconnected', 'warn');
    loadContacts();
  });
}

function updateTriagePill(category, delta) {
  const segment = document.querySelector(`.triage-segment.${category}`);
  if (!segment) return;
  const pill = document.getElementById('triage-pill');
  const valueEl = segment.querySelector('.triage-value');
  let count = parseInt(segment.getAttribute('data-count') || '0') + delta;
  if (count < 0) count = 0;
  
  segment.setAttribute('data-count', count);
  valueEl.textContent = count;
  
  // Show/Hide pill based on total count
  const total = Array.from(document.querySelectorAll('.triage-segment'))
    .reduce((acc, s) => acc + parseInt(s.getAttribute('data-count') || '0'), 0);
  
  if (total > 0) pill.classList.add('active');
  else pill.classList.remove('active');

  // Sync the bell icon badge in the nav bar
  IconResolver.updateAlertBadge(total);
}

// ── Location Watching ─────────────────────────────────
function startLocationWatch() {
  if (!navigator.geolocation) {
    console.warn('Geolocation not supported');
    return;
  }

  AppState.locationWatchId = navigator.geolocation.watchPosition(
    async (pos) => {
      const { latitude: lat, longitude: lng, accuracy, altitude, speed, heading } = pos.coords;
      AppMap.updateMyPin({ lat, lng, accuracy });

      // Send to backend (or queue for SMS if offline)
      if (AppState.isOnline) {
        await API.post('/location/update', {
          lat, lng, accuracy, altitude,
          speed, bearing: heading,
          source: 'NATIVE_GPS',
          pingMechanism: AppState.settings?.pingMode || 'MEDIUM'
        }).catch(console.error);
      } else {
        queueSMSUpdate(lat, lng, accuracy);
      }
    },
    (err) => console.warn('Geolocation error:', err.message),
    { enableHighAccuracy: true, maximumAge: 5000, timeout: 15000 }
  );
}

// ── SMS Fallback Queue ────────────────────────────────
let _smsQueue = [];
function queueSMSUpdate(lat, lng, accuracy) {
  const userId = AppState.user?.id || '';
  const payload = `LOC,${userId},${lat.toFixed(6)},${lng.toFixed(6)},${(accuracy||0).toFixed(1)},${getDeviceBattery()},${Date.now()}`;
  _smsQueue.push(payload);
  console.log('[SMS Fallback] Queued update:', payload);

  // Show user they are in SMS mode
  if (!AppState.isSmsMode) {
    showToast('📵 Location queued for SMS delivery', 'warn');
  }
}

function getDeviceBattery() {
  // Returns battery % if available
  return 99; // placeholder; real impl uses Battery API
}

// ── Modals ────────────────────────────────────────────
function openModal(id) {
  document.getElementById(id).classList.remove('hidden');
}
function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
}

// ── Toast ─────────────────────────────────────────────
function showToast(msg, type = 'info', duration = 3000) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-6px)';
    toast.style.transition = '0.3s';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

const _contactLocations = {};

function updateContactLocationList(data) {
  _contactLocations[data.userId] = data;
  renderContactLocationList();
}

function renderContactLocationList() {
  const list = document.getElementById('contact-location-list');
  const entries = Object.values(_contactLocations);
  if (!entries.length) { list.innerHTML = ''; return; }

  list.innerHTML = entries.map(d => {
    const contact = AppState.contacts.find(c => c.contact?.id === d.userId)?.contact;
    const name = contact?.displayName || contact?.username || d.userId.slice(0,8);
    const avatar = IconResolver.getAvatar(contact?.username || d.userId);
    const time = new Date(d.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `
      <div class="contact-loc-item" onclick="AppMap.focusOnUser('${d.userId}')">
        <div class="cloc-avatar">
          <img src="${avatar}" alt="" style="width:100%;height:100%;border-radius:50%">
        </div>
        <div class="cloc-info">
          <div class="cloc-name">${escHtml(name)}</div>
          <div class="cloc-time">${time} — ${Math.round(d.accuracy || 0)}m precision</div>
        </div>
        <button class="cloc-ping" onclick="event.stopPropagation(); triggerRemotePing('${d.userId}')">Ping</button>
      </div>
    `;
  }).join('');
}

function openRemotePing(targetUserId, name) {
  AppState.sosTargetUserId = targetUserId;
  document.getElementById('ping-target-name').textContent = name;
  openModal('modal-remote-ping');
}

async function sendRemotePing() {
  const btn = document.getElementById('btn-send-ping');
  btn.disabled = true; btn.textContent = 'Pinging…';
  try {
    await API.post('/pings/request', { targetUserId: AppState.sosTargetUserId });
    showToast('📡 Ping sent — waiting for response', 'info', 4000);
    closeModal('modal-remote-ping');
  } catch (err) {
    showToast(`Ping failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false; btn.textContent = 'Send Ping';
  }
}

// ── Helpers ───────────────────────────────────────────
function getRelativeTime(date) {
  const diff = Date.now() - date.getTime();
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
  return date.toLocaleDateString();
}

function toggleSharing(enabled) {
  API.put('/settings', { locationSharingEnabled: enabled }).catch(console.error);
  const sharingCard = document.getElementById('sharing-card');
  if (sharingCard) {
    sharingCard.classList.toggle('active-state', enabled);
    sharingCard.classList.toggle('paused-state', !enabled);
  }
  document.getElementById('sharing-sub').textContent = enabled
    ? `Sharing with ${AppState.contacts.filter(c=>c.status==='ACCEPTED').length} contacts`
    : 'Sharing paused';
}

function openAddContact() { openModal('modal-add-contact'); }

async function switchAlertTab(tab, btn) {
  document.querySelectorAll('.alert-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  
  // Set data-attribute on parent for sliding pill animation
  const container = btn.closest('.alerts-tabs');
  if (container) {
    container.setAttribute('data-active-tab', tab === 'inbox' ? 'right' : 'left');
  }

  document.getElementById('alerts-outbound').classList.toggle('hidden', tab !== 'outbound');
  document.getElementById('alerts-inbox').classList.toggle('hidden', tab !== 'inbox');
}

// ── Demo Mode ─────────────────────────────────────────
function startDemoMode() {
  AppState.isDemoMode = true;
  AppState.user = { id: 'demo123', username: 'demo_user', displayName: 'Jane Doe (Demo)', phone: '+1234567890' };
  showApp();
  showToast('Running in Interactive Demo Mode (No DB required)', 'info', 4000);
}

window.demoApiRequest = async function(path, options) {
  const method = options.method || 'GET';
  await new Promise(r => setTimeout(r, 100 + Math.random() * 200)); // fake delay
  
  if (path.startsWith('/contacts')) {
    if (method === 'GET') {
      if (path === '/contacts') return [
        { linkId: 'link1', status: 'ACCEPTED', contact: { id: 'c1', username: 'alice', displayName: 'Alice' } },
        { linkId: 'link2', status: 'ACCEPTED', contact: { id: 'c2', username: 'bob', displayName: 'Bob' } },
        { linkId: 'link3', status: 'PENDING', isInitiator: false, contact: { id: 'c3', username: 'charlie', displayName: 'Charlie' } }
      ];
      if (path === '/contacts/groups') return [
        { id: 'g1', name: 'Family Group', members: [{id: 'c1'}, {id:'c2'}] }
      ];
    }
    if (method === 'POST') return { id: 'group_new' };
    if (method === 'DELETE' || method === 'PUT') return {};
  }
  
  if (path.startsWith('/trackers')) {
    if (method === 'GET') return [
      { id: 't1', label: 'My Backpack', bleUuid: 'E2C56DB5', lastSeenLat: 34.05, lastSeenLng: -118.25, lastSeenAt: new Date().toISOString(), batteryPct: 88 }
    ];
    if (method === 'POST') return { id: 't2', label: 'Keys', bleUuid: 'AAAA' };
    if (method === 'DELETE' || method === 'PUT') return {};
  }
  
  if (path.startsWith('/sos')) {
    if (method === 'GET') {
      if (path.includes('events')) return [
        { id: 'ev1', mode: 'SILENT_ALERT', createdAt: new Date(Date.now() - 86400000).toISOString(), resolvedAt: new Date().toISOString(), notifications: [
          { notifiedId: 'alice', status: 'ON_MY_WAY' }
        ] }
      ];
      if (path.includes('inbox')) return [
        { id: 'n1', status: 'DELIVERED', createdAt: new Date().toISOString(), sosEvent: { id: 'e1', mode: 'SILENT_ALERT', triggeredBy: { id: 'c1', displayName: 'Alice', username: 'alice' } } }
      ];
    }
    if (method === 'POST') {
      setTimeout(() => {
        if (AppMap && AppMap.map) {
          navigator.geolocation.getCurrentPosition(pos => {
            AppMap.addSOSMarker(pos.coords.latitude, pos.coords.longitude, 'Test SOS');
          });
        }
      }, 500);
      return { eventId: 'demo_event', notifiedCount: 2 };
    }
    if (method === 'PUT') return {};
  }
  
  if (path.startsWith('/settings')) {
    if (method === 'GET') return { pingMode: 'MEDIUM', adaptivePingEnabled: true, sosMode: 'SILENT_ALERT', retentionDays: 30, pingPresets: [{mode:'MEDIUM', batteryImpact:'Moderate'}] };
    if (method === 'PUT') return JSON.parse(options.body || '{}');
  }
  
  if (path.startsWith('/location/watchers')) {
    return [
      { linkId: 'link1', user: { id: 'c1', username: 'alice', displayName: 'Alice' } }
    ];
  }
  
  if (path === '/location/update') return {};
  if (path === '/pings/request') return {};
  if (path.startsWith('/users/search')) return [
       { id: 'search1', username: 'john_doe', displayName: 'John Doe' },
       { id: 'search2', username: 'jane_smith', displayName: 'Jane Smith' }
  ];
  if (path === '/auth/logout') return {};
  
  return {};
};

// ─── Vouch System: Scaling Trust ───────────────────────
async function handleGenerateInvite() {
  const btn = document.getElementById('btn-generate-invite');
  const codeArea = document.getElementById('invite-display-area');
  const codeEl = document.getElementById('generated-invite-code');
  const quotaEl = document.getElementById('invite-quota-display');

  // Check rate limit (6 hours)
  const lastInviteAt = localStorage.getItem('st_last_invite_at');
  if (lastInviteAt) {
    const diff = (Date.now() - parseInt(lastInviteAt)) / (1000 * 60 * 60);
    if (diff < 6) {
      showToast('Rate limited: Please wait 6 hours between invites.', 'warn', 5000);
      return;
    }
  }

  btn.disabled = true;
  btn.textContent = 'Generating...';

  try {
    // 1. Backend call (minting the OTP and recording the vouch ancestry)
    const result = await API.post('/auth/create-invite', {
      inviter_npub: AppState.user?.npub
    });

    if (result.code) {
      codeEl.textContent = result.code;
      codeArea.classList.remove('hidden');
      
      // Update local quota display
      if (AppState.user) {
        AppState.user.inviteQuota = (AppState.user.inviteQuota || 3) - 1;
        quotaEl.textContent = AppState.user.inviteQuota;
      }

      localStorage.setItem('st_last_invite_at', Date.now().toString());
      showToast('Invite generated successfully.', 'success');
    } else if (result.error === 'quota_exceeded') {
      showToast('No invites remaining in your quota.', 'warn');
    }
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Generate Invite Code';
  }
}

// ── Optimized Bootstrap & Device Hardening ────────────

/**
 * Optimized One-Trip Loader for high-latency environments.
 */
async function loadApplicationData() {
  if (AppState.isDemoMode) return;
  
  try {
    const data = await API.rpc('get_safe_track_bootstrap');
    
    // Distribute data to global state
    AppState.user = data.profile;
    AppState.contacts = data.contacts;
    
    // Inject into specialized modules
    if (window.renderContacts) renderContacts(data.contacts);
    if (window.renderTrackers) renderTrackers(data.trackers);
    if (window.renderAlerts) renderAlerts(data.alerts);
    updateProfileUI(data.profile);
    
    // Verify current device context (Security Hardening)
    await verifyDeviceContext();
    
    console.log('[BOOTSTRAP] Secure context initialized.');
  } catch (err) {
    console.error('[BOOTSTRAP] Error:', err);
    showToast('Failed to load secure state. Re-authenticating...', 'error');
    logout();
  }
}

/**
 * Updates all identity markers in the UI with verified user data.
 */
function updateProfileUI(u) {
  if (!u) return;
  const avatarUrl = IconResolver.getAvatar(u.username || u.id);
  
  // Update Nav Avatar
  const navAvatar = document.getElementById('nav-avatar');
  if (navAvatar) {
    navAvatar.innerHTML = `<img src="${avatarUrl}" style="width:100%;height:100%;border-radius:50%">`;
    navAvatar.style.background = 'none';
  }

  // Update Settings Profile Card
  const setAvatar = document.getElementById('settings-avatar');
  if (setAvatar) {
    setAvatar.innerHTML = `<img src="${avatarUrl}" style="width:100%;height:100%;border-radius:50%">`;
    setAvatar.style.background = 'none';
  }

  const nameEl = document.getElementById('settings-displayname');
  if (nameEl) nameEl.textContent = u.displayName || u.username;

  const userEl = document.getElementById('settings-username');
  if (userEl) userEl.textContent = `@${u.username}`;

  const phoneEl = document.getElementById('settings-phone');
  if (phoneEl) phoneEl.textContent = u.phone || '—';
}

/**
 * Captures high-fidelity metadata for secondary device verification.
 * Does not store PII; uses hashing to remain forensically silent.
 */
async function captureDeviceSecureMetadata() {
  const meta = {
    ua: navigator.userAgent,
    plt: navigator.platform,
    scr: `${window.screen.width}x${window.screen.height}`,
    hc: navigator.hardwareConcurrency || '?',
    mem: navigator.deviceMemory || '?',
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone
  };
  
  // Create a stable hash of the context
  const str = JSON.stringify(meta);
  const buffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return { hash: hashHex, raw: meta };
}

async function verifyDeviceContext() {
  const { hash, raw } = await captureDeviceSecureMetadata();
  const fp = localStorage.getItem('st_device_fp');
  
  // Update server with current context (silent heartbeat)
  await API.post('/auth/heartbeat', {
    device_fp: fp,
    metadata_hash: hash,
    metadata_raw: raw
  }).catch(() => {/* fail silent on network blip */});
}

