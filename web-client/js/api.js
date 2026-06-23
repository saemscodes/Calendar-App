/**
 * SafeTrack — API Client
 * Thin wrapper over fetch() with JWT auth and refresh logic.
 */

const API = (() => {
  // Use Supabase REST if configured, otherwise fall back to local Node backend
  const SUPABASE_URL = window.SUPABASE_URL || '';
  const SUPABASE_ANON_KEY = window.SUPABASE_ANON_KEY || '';
  const USE_SUPABASE = !!SUPABASE_URL;
  const BASE = USE_SUPABASE ? `${SUPABASE_URL}/rest/v1` : '/api/v1';

  function getToken() { return localStorage.getItem('st_access_token'); }
  function getRefresh() { return localStorage.getItem('st_refresh_token'); }
  function saveTokens(access, refresh) {
    localStorage.setItem('st_access_token', access);
    if (refresh) localStorage.setItem('st_refresh_token', refresh);
  }
  function clearTokens() {
    localStorage.removeItem('st_access_token');
    localStorage.removeItem('st_refresh_token');
    localStorage.removeItem('st_user');
  }

  async function refreshAccessToken() {
    const refresh = getRefresh();
    if (!refresh) return false;
    try {
      const resp = await fetch(`${BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: refresh })
      });
      if (!resp.ok) { clearTokens(); return false; }
      const data = await resp.json();
      saveTokens(data.accessToken, data.refreshToken);
      return true;
    } catch { return false; }
  }

  async function request(path, options = {}, retry = true) {
    if (window.AppState && window.AppState.isDemoMode && typeof window.demoApiRequest === 'function') {
      return window.demoApiRequest(path, options);
    }
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    // Supabase requires apikey header with anon key
    if (USE_SUPABASE && SUPABASE_ANON_KEY) headers['apikey'] = SUPABASE_ANON_KEY;

    const resp = await fetch(`${BASE}${path}`, { ...options, headers });

    if (resp.status === 401 && retry) {
      const ok = await refreshAccessToken();
      if (ok) return request(path, options, false);
      clearTokens();
      window.location.reload();
      return null;
    }

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw Object.assign(new Error(data.error || 'Request failed'), { status: resp.status, data });
    return data;
  }

  return {
    get: (path, opts) => request(path, { method: 'GET', ...opts }),
    post: (path, body, opts) => request(path, { method: 'POST', body: JSON.stringify(body), ...opts }),
    put: (path, body, opts) => request(path, { method: 'PUT', body: JSON.stringify(body), ...opts }),
    del: (path, opts) => request(path, { method: 'DELETE', ...opts }),
    rpc: (name, body, opts) => request(`/rpc/${name}`, { method: 'POST', body: JSON.stringify(body), ...opts }),

    // Auth helpers
    saveTokens,
    clearTokens,
    getToken,
    getRefresh,

    // User helpers
    saveUser: (u) => localStorage.setItem('st_user', JSON.stringify(u)),
    getUser: () => {
      try { return JSON.parse(localStorage.getItem('st_user')); } catch { return null; }
    }
  };
})();
