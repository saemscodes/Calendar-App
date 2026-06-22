/**
 * SafeTrack — Nostr P2P & Persistence Layer
 * GAP 3 & 4 Hardening: IndexedDB and Health Monitoring
 */

const DB_NAME = 'SafeTrackP2P';
const DB_VERSION = 1;

const NostrP2P = {
  db: null,

  async init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('contact_relays')) {
          db.createObjectStore('contact_relays', { keyPath: 'npub' });
        }
        if (!db.objectStoreNames.contains('relay_status')) {
          db.createObjectStore('relay_status', { keyPath: 'url' });
        }
      };
      request.onsuccess = (e) => {
        this.db = e.target.result;
        this.loadCacheIntoState();
        this.startHealthWorker(); // Periodically check relay health
        resolve();
      };
      request.onerror = reject;
    });
  },

  async loadCacheIntoState() {
    if (!this.db) return;
    const tx = this.db.transaction('contact_relays', 'readonly');
    const store = tx.objectStore('contact_relays');
    const all = store.getAll();
    all.onsuccess = () => {
      if (!AppState.contactRelays) AppState.contactRelays = {};
      all.result.forEach(item => {
        AppState.contactRelays[item.npub] = item.relays;
      });
    };
  },

  async saveContactRelays(npub, relays) {
    if (!this.db) return;
    const tx = this.db.transaction('contact_relays', 'readwrite');
    tx.objectStore('contact_relays').put({ npub, relays, updated_at: Date.now() });
  },

  startHealthWorker() {
    // Ping all primary relays every 5 minutes
    this.checkRelayHealth();
    setInterval(() => this.checkRelayHealth(), 5 * 60 * 1000);
  },

  async checkRelayHealth() {
    const allRelays = [
      'wss://relay.damus.io',
      'wss://nos.lol',
      'wss://relay.nostr.band',
      'wss://nostr.wine',
      'wss://relay.snort.social'
    ];

    allRelays.forEach(url => {
      const start = Date.now();
      const ws = new WebSocket(url);
      
      const timeout = setTimeout(() => {
        // We only mark it offline here. We do not call ws.close() 
        // to avoid the native "closed before established" console error.
        this.updateRelayStatus(url, 'offline', 9999);
      }, 5000);

      ws.onopen = () => {
        const latency = Date.now() - start;
        ws.close();
        if (latency <= 5000) {
          clearTimeout(timeout);
          this.updateRelayStatus(url, 'online', latency);
        }
      };
      
      ws.onerror = () => {
        clearTimeout(timeout);
        this.updateRelayStatus(url, 'offline', 9999);
      };
    });
  },

  updateRelayStatus(url, status, latency) {
    if (!AppState.relayStatus) AppState.relayStatus = {};
    AppState.relayStatus[url] = { status, latency, last_check: Date.now() };
    
    // Save to IDB for offline reference
    if (this.db) {
      const tx = this.db.transaction('relay_status', 'readwrite');
      tx.objectStore('relay_status').put({ url, status, latency, last_check: Date.now() });
    }

    // Update UI if on settings or alert screen
    const badge = document.getElementById('network-health-badge');
    if (badge) {
      const online = Object.values(AppState.relayStatus).filter(r => r.status === 'online').length;
      badge.textContent = `${online}/${Object.keys(AppState.relayStatus).length} Relays`;
      badge.className = online > 2 ? 'health-good' : 'health-critical';
    }
  },

  getBestRelays(count = 3) {
    if (!AppState.relayStatus) return [];
    return Object.entries(AppState.relayStatus)
      .filter(([url, data]) => data.status === 'online')
      .sort((a, b) => a[1].latency - b[1].latency)
      .slice(0, count)
      .map(entry => entry[0]);
  }
};

// Auto-init
window.addEventListener('load', () => NostrP2P.init());
